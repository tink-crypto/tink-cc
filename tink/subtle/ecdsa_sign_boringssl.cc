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
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

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
      break;
    case EcdsaParameters::CurveType::kNistP521:
      return NIST_P521;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid curve in EcdsaVerifyBoringSsl::New: ",
                       curve_type));
  }
}

absl::StatusOr<HashType> ConvertHashType(EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return SHA256;
    case EcdsaParameters::HashType::kSha384:
      return SHA384;
      break;
    case EcdsaParameters::HashType::kSha512:
      return SHA512;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid hash type in EcdsaVerifyBoringSsl::New: ",
                       hash_type));
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
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat(
              "Invalid signature encoding in EcdsaVerifyBoringSsl::New: ",
              signature_encoding));
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> EcdsaSignBoringSsl::New(
    const EcdsaPrivateKey& key) {
  SubtleUtilBoringSSL::EcKey subtle_ec_key;
  const EcPoint& ec_point = key.GetPublicKey()
      .GetPublicPoint(GetPartialKeyAccess());
  subtle_ec_key.pub_x = std::string(ec_point.GetX().GetValue());
  subtle_ec_key.pub_y = std::string(ec_point.GetY().GetValue());
  subtle_ec_key.priv = util::SecretDataFromStringView(
      key.GetPrivateKeyValue(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()));
  absl::StatusOr<subtle::EllipticCurveType> converted_curve_type =
      ConvertCurveType(key.GetPublicKey().GetParameters().GetCurveType());
  if (!converted_curve_type.ok()) {
    return converted_curve_type.status();
  }
  subtle_ec_key.curve = *converted_curve_type;

  absl::StatusOr<HashType> converted_hash_type =
      ConvertHashType(key.GetPublicKey().GetParameters().GetHashType());
  if (!converted_hash_type.ok()) {
    return converted_hash_type.status();
  }

  absl::StatusOr<EcdsaSignatureEncoding> converted_signature_encoding =
      ConvertSignatureEncoding(
          key.GetPublicKey().GetParameters().GetSignatureEncoding());
  if (!converted_signature_encoding.ok()) {
    return converted_signature_encoding.status();
  }
  return New(
      subtle_ec_key, *converted_hash_type, *converted_signature_encoding,
      key.GetPublicKey().GetOutputPrefix(),
      key.GetParameters().GetVariant() == EcdsaParameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> EcdsaSignBoringSsl::New(
    const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
    EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  auto status = internal::CheckFipsCompatibility<EcdsaSignBoringSsl>();
  if (!status.ok()) return status;

  // Check if the hash type is safe to use.
  absl::Status is_safe = internal::IsHashTypeSafeForSignature(hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }
  absl::StatusOr<const EVP_MD*> hash = internal::EvpHashFromHashType(hash_type);
  if (!hash.ok()) {
    return hash.status();
  }

  absl::StatusOr<std::unique_ptr<internal::EcdsaRawSignBoringSsl>> raw_sign =
      internal::EcdsaRawSignBoringSsl::New(ec_key, encoding);
  if (!raw_sign.ok()) return raw_sign.status();

  return {absl::WrapUnique(new EcdsaSignBoringSsl(
      *hash, std::move(*raw_sign), output_prefix, message_suffix))};
}

absl::StatusOr<std::string> EcdsaSignBoringSsl::SignWithoutPrefix(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  // Compute the digest.
  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (1 != EVP_Digest(data.data(), data.size(), digest, &digest_size, hash_,
                      nullptr)) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not compute digest.");
  }

  // Compute the signature.
  return raw_signer_->Sign(
      absl::string_view(reinterpret_cast<char*>(digest), digest_size));
}

absl::StatusOr<std::string> EcdsaSignBoringSsl::Sign(
    absl::string_view data) const {
  absl::StatusOr<std::string> signature_without_prefix_;
  if (message_suffix_.empty()) {
    signature_without_prefix_ = SignWithoutPrefix(data);
  } else {
    signature_without_prefix_ =
        SignWithoutPrefix(absl::StrCat(data, message_suffix_));
  }
  if (!signature_without_prefix_.ok()) {
    return signature_without_prefix_.status();
  }
  if (output_prefix_.empty()) {
    return signature_without_prefix_;
  }
  return absl::StrCat(output_prefix_, *signature_without_prefix_);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
