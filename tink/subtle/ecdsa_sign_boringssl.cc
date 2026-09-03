// Copyright 2017 Google LLC
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

#include "tink/subtle/ecdsa_sign_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/opensslv.h"  // To get OPENSSL_IS_BORINGSSL if needed
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"
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
          "Invalid curve in EcdsaSignBoringSsl::New: ", curve_type));
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
          "Invalid hash type in EcdsaSignBoringSsl::New: ", hash_type));
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
          "Invalid signature encoding in EcdsaSignBoringSsl::New: ",
          signature_encoding));
  }
}

// Impl class for `EcdsaSignBoringSsl`. This allows us to not expose the
// BoringSsl hash function type in the public header.
// Given:
// - the hash function h (given by `hash_`),
// - the signer S (given by `raw_signer_`, which signs the digest),
// - the output prefix o of the key (given by `output_prefix_`),
// - and the message suffix s (given by `message_suffix),
// EcdsaSignBoringSsl::Sign(data) computes:
// o || S(h( data || s))
class EcdsaSignBoringSslImpl : public EcdsaSignBoringSsl {
 public:
  EcdsaSignBoringSslImpl(
      const EVP_MD* hash,
      std::unique_ptr<internal::EcdsaRawSignBoringSsl> digest_signer,
      absl::string_view output_prefix, absl::string_view message_suffix)
      : hash_(hash),
        digest_signer_(std::move(digest_signer)),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

 private:
  absl::StatusOr<std::string> SignWithoutPrefix(absl::string_view data) const;

  const EVP_MD* hash_;  // Owned by BoringSSL.
  std::unique_ptr<internal::EcdsaRawSignBoringSsl> digest_signer_;
  std::string output_prefix_;
  std::string message_suffix_;
};

absl::StatusOr<std::string> EcdsaSignBoringSslImpl::SignWithoutPrefix(
    absl::string_view data) const {
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

  // Compute the signature.
  return digest_signer_->SignDigest(
      absl::string_view(reinterpret_cast<char*>(digest), digest_size));
}

absl::StatusOr<std::string> EcdsaSignBoringSslImpl::Sign(
    absl::string_view data) const {
  std::string signature_without_prefix;
  if (message_suffix_.empty()) {
    ABSL_ASSIGN_OR_RETURN(signature_without_prefix, SignWithoutPrefix(data));
  } else {
    ABSL_ASSIGN_OR_RETURN(
        signature_without_prefix,
        SignWithoutPrefix(absl::StrCat(data, message_suffix_)));
  }
  if (output_prefix_.empty()) {
    return signature_without_prefix;
  }
  return absl::StrCat(output_prefix_, signature_without_prefix);
}

}  // namespace

absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> EcdsaSignBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<EcdsaSignBoringSsl>());

  // Check if the hash type is safe to use.
  ABSL_RETURN_IF_ERROR(internal::IsHashTypeSafeForSignature(hash_type));
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* hash,
                        internal::EvpHashFromHashType(hash_type));

  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<internal::EcdsaRawSignBoringSsl> raw_sign,
      internal::EcdsaRawSignBoringSsl::New(ec_key, encoding));

  return std::make_unique<EcdsaSignBoringSslImpl>(
      hash, std::move(raw_sign), output_prefix, message_suffix);
}

absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> EcdsaSignBoringSsl::New(
    const EcdsaPrivateKey& key) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<EcdsaSignBoringSsl>());

  ABSL_ASSIGN_OR_RETURN(
      subtle::EllipticCurveType converted_curve_type,
      ConvertCurveType(key.GetPublicKey().GetParameters().GetCurveType()));
  ABSL_ASSIGN_OR_RETURN(
      HashType converted_hash_type,
      ConvertHashType(key.GetPublicKey().GetParameters().GetHashType()));
  ABSL_ASSIGN_OR_RETURN(
      EcdsaSignatureEncoding converted_signature_encoding,
      ConvertSignatureEncoding(
          key.GetPublicKey().GetParameters().GetSignatureEncoding()));

  ABSL_ASSIGN_OR_RETURN(internal::SslUniquePtr<EC_GROUP> group,
                        internal::EcGroupFromCurveType(converted_curve_type));
  internal::SslUniquePtr<EC_KEY> ec_key(EC_KEY_new());
  EC_KEY_set_group(ec_key.get(), group.get());

  const EcPoint& public_point =
      key.GetPublicKey().GetPublicPoint(GetPartialKeyAccess());
  ABSL_ASSIGN_OR_RETURN(
      internal::SslUniquePtr<EC_POINT> pub_key,
      internal::GetEcPoint(converted_curve_type, public_point.GetX().GetValue(),
                           public_point.GetY().GetValue()));
  if (!EC_KEY_set_public_key(ec_key.get(), pub_key.get())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
  }

  ABSL_RETURN_IF_ERROR(
      internal::CallWithCoreDumpProtection([&]() -> absl::Status {
        ABSL_ASSIGN_OR_RETURN(
            internal::SslUniquePtr<BIGNUM> priv,
            internal::StringToBignum(
                key.GetPrivateKey(GetPartialKeyAccess())
                    .GetSecret(InsecureSecretKeyAccess::Get())));
        if (1 != EC_KEY_set_private_key(ec_key.get(), priv.get())) {
          return absl::InternalError(absl::StrCat(
              "EC_KEY_set_private_key failed: ", internal::GetSslErrors()));
        }
        return absl::OkStatus();
      }));

  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<internal::EcdsaRawSignBoringSsl> raw_sign,
      internal::EcdsaRawSignBoringSsl::New(std::move(ec_key),
                                           converted_signature_encoding));

  ABSL_ASSIGN_OR_RETURN(const EVP_MD* hash,
                        internal::EvpHashFromHashType(converted_hash_type));

  return std::make_unique<EcdsaSignBoringSslImpl>(
      hash, std::move(raw_sign), key.GetPublicKey().GetOutputPrefix(),
      key.GetParameters().GetVariant() == EcdsaParameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
