// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/ecdsa_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "openssl/bn.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

absl::StatusOr<subtle::EllipticCurveType> ConvertCurveType(
    EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return NIST_P256;
    case EcdsaParameters::CurveType::kNistP384:
      return NIST_P384;
    case EcdsaParameters::CurveType::kNistP521:
      return NIST_P521;
    default:
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid curve in EcdsaVerifyBoringSsl::New: ", curve_type));
  }
}

absl::StatusOr<HashType> ConvertHashType(EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return SHA256;
    case EcdsaParameters::HashType::kSha384:
      return SHA384;
    case EcdsaParameters::HashType::kSha512:
      return SHA512;
    default:
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid hash type in EcdsaVerifyBoringSsl::New: ", hash_type));
  }
}

absl::StatusOr<EcdsaSignatureEncoding> ConvertSignatureEncoding(
    EcdsaParameters::SignatureEncoding signature_encoding) {
  switch (signature_encoding) {
    case EcdsaParameters::SignatureEncoding::kIeeeP1363:
      return IEEE_P1363;
    case EcdsaParameters::SignatureEncoding::kDer:
      return DER;
    default:
      return absl::InvalidArgumentError(absl::StrCat(
          "Invalid signature encoding in EcdsaVerifyBoringSsl::New: ",
          signature_encoding));
  }
}

class EcdsaVerifyBoringSslImpl : public EcdsaVerifyBoringSsl {
 public:
  EcdsaVerifyBoringSslImpl(internal::SslUniquePtr<EC_KEY> key,
                           const EVP_MD* hash, EcdsaSignatureEncoding encoding,
                           absl::string_view output_prefix,
                           absl::string_view message_suffix)
      : key_(std::move(key)),
        hash_(hash),
        encoding_(encoding),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

 private:
  absl::Status VerifyWithoutPrefix(absl::string_view signature,
                                   absl::string_view data) const;

  internal::SslUniquePtr<EC_KEY> key_;
  const EVP_MD* hash_;  // Owned by BoringSSL.
  EcdsaSignatureEncoding encoding_;
  const std::string output_prefix_;
  const std::string message_suffix_;
};

absl::Status EcdsaVerifyBoringSslImpl::VerifyWithoutPrefix(
    absl::string_view signature, absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  // Compute the digest.
  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, hash_,
                      nullptr)) {
    return absl::InternalError("Could not compute digest.");
  }

  std::string derSig(signature);
  if (encoding_ == subtle::EcdsaSignatureEncoding::IEEE_P1363) {
    const EC_GROUP* group = EC_KEY_get0_group(key_.get());
    ABSL_ASSIGN_OR_RETURN(derSig,
                          internal::EcSignatureIeeeToDer(group, signature));
  }

  // Verify the signature.
  if (1 != ECDSA_verify(0 /* unused */, digest, digest_size,
                        reinterpret_cast<const uint8_t*>(derSig.data()),
                        derSig.size(), key_.get())) {
    // signature is invalid
    return absl::InvalidArgumentError("Signature is not valid.");
  }
  // signature is valid
  return absl::OkStatus();
}

absl::Status EcdsaVerifyBoringSslImpl::Verify(absl::string_view signature,
                                              absl::string_view data) const {
  if (output_prefix_.empty() && message_suffix_.empty()) {
    return VerifyWithoutPrefix(signature, data);
  }
  if (!absl::StartsWith(signature, output_prefix_)) {
    return absl::InvalidArgumentError("OutputPrefix does not match");
  }
  // Creates a copy of the data with the message_suffix_ appended if not empty.
  // Needs to stay alive until this method is done, as data will point to it.
  std::string data_with_suffix;
  if (!message_suffix_.empty()) {
    data_with_suffix = absl::StrCat(data, message_suffix_);
    data = data_with_suffix;
  }
  return VerifyWithoutPrefix(absl::StripPrefix(signature, output_prefix_),
                             data);
}

}  // namespace

absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    const EcdsaPublicKey& public_key) {
  ABSL_ASSIGN_OR_RETURN(
      subtle::EllipticCurveType converted_curve_type,
      ConvertCurveType(public_key.GetParameters().GetCurveType()));
  ABSL_ASSIGN_OR_RETURN(
      HashType converted_hash_type,
      ConvertHashType(public_key.GetParameters().GetHashType()));
  ABSL_ASSIGN_OR_RETURN(EcdsaSignatureEncoding converted_signature_encoding,
                        ConvertSignatureEncoding(
                            public_key.GetParameters().GetSignatureEncoding()));

  ABSL_ASSIGN_OR_RETURN(internal::SslUniquePtr<EC_GROUP> group,
                        internal::EcGroupFromCurveType(converted_curve_type));
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());

  ABSL_ASSIGN_OR_RETURN(
      internal::SslUniquePtr<EC_POINT> pub_key,
      internal::GetEcPoint(
          converted_curve_type,
          public_key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue(),
          public_key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue()));
  if (!EC_KEY_set_public_key(key.get(), pub_key.get())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  return New(std::move(key), converted_hash_type, converted_signature_encoding,
             public_key.GetOutputPrefix(),
             public_key.GetParameters().GetVariant() ==
                     EcdsaParameters::Variant::kLegacy
                 ? std::string(1, 0)
                 : "");
}

absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  // Check curve.
  ABSL_ASSIGN_OR_RETURN(internal::SslUniquePtr<EC_GROUP> group,
                        internal::EcGroupFromCurveType(ec_key.curve));
  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  EC_KEY_set_group(key.get(), group.get());

  // Check key.
  ABSL_ASSIGN_OR_RETURN(
      internal::SslUniquePtr<EC_POINT> pub_key,
      internal::GetEcPoint(ec_key.curve, ec_key.pub_x, ec_key.pub_y));
  if (!EC_KEY_set_public_key(key.get(), pub_key.get())) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }
  return New(std::move(key), hash_type, encoding, output_prefix,
             message_suffix);
}

absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> EcdsaVerifyBoringSsl::New(
    internal::SslUniquePtr<EC_KEY> ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<EcdsaVerifyBoringSsl>());

  // Check if the hash type is safe to use.
  ABSL_RETURN_IF_ERROR(internal::IsHashTypeSafeForSignature(hash_type));
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* hash,
                        internal::EvpHashFromHashType(hash_type));
  return std::make_unique<EcdsaVerifyBoringSslImpl>(
      std::move(ec_key), hash, encoding, output_prefix, message_suffix);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
