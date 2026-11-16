// Copyright 2026 Google LLC
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

#include "tink/signature/internal/rsa_ssa_pkcs1_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

absl::Status RsaSsaPkcs1Verify(RSA* rsa, const EVP_MD* sig_hash,
                               absl::string_view signature,
                               absl::string_view data, bool append_null_byte) {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = EnsureStringNonNull(data);

  ABSL_ASSIGN_OR_RETURN(
      std::string digest,
      append_null_byte
          ? ComputeHash({data, absl::string_view("\0", 1)}, *sig_hash)
          : ComputeHash(data, *sig_hash));

  if (RSA_verify(EVP_MD_type(sig_hash),
                 /*digest=*/reinterpret_cast<const uint8_t*>(digest.data()),
                 /*digest_len=*/digest.size(),
                 /*sig=*/reinterpret_cast<const uint8_t*>(signature.data()),
                 /*sig_len=*/signature.length(),
                 /*rsa=*/rsa) != 1) {
    // Signature is invalid.
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Signature is not valid.");
  }

  return absl::OkStatus();
}

class RsaSsaPkcs1VerifyBoringSslImpl final : public PublicKeyVerify {
 public:
  static constexpr FipsCompatibility kFipsStatus =
      FipsCompatibility::kRequiresBoringCrypto;

  RsaSsaPkcs1VerifyBoringSslImpl(SslUniquePtr<RSA> rsa, const EVP_MD* sig_hash)
      : rsa_(std::move(rsa)), sig_hash_(sig_hash) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    return RsaSsaPkcs1Verify(rsa_.get(), sig_hash_, signature, data,
                             /*append_null_byte=*/false);
  }

 private:
  const SslUniquePtr<RSA> rsa_;
  const EVP_MD* const sig_hash_;  // Owned by BoringSSL.
};

// Handles Tink output-prefix and legacy '\0'-suffix framing separately so
// unprefixed verifiers do not carry unused prefix/suffix state.
class RsaSsaPkcs1VerifyWithPrefix final : public PublicKeyVerify {
 public:
  RsaSsaPkcs1VerifyWithPrefix(SslUniquePtr<RSA> rsa, const EVP_MD* sig_hash,
                              absl::string_view output_prefix,
                              bool append_null_byte)
      : rsa_(std::move(rsa)),
        sig_hash_(sig_hash),
        output_prefix_(output_prefix),
        append_null_byte_(append_null_byte) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    if (!absl::ConsumePrefix(&signature, output_prefix_)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "OutputPrefix does not match");
    }
    return RsaSsaPkcs1Verify(rsa_.get(), sig_hash_, signature, data,
                             append_null_byte_);
  }

 private:
  const SslUniquePtr<RSA> rsa_;
  const EVP_MD* const sig_hash_;  // Owned by BoringSSL.
  const std::string output_prefix_;
  const bool append_null_byte_;
};

// Returns the BoringSSL hash for `hash_type` if it may be used for signatures.
absl::StatusOr<const EVP_MD*> GetSigHash(subtle::HashType hash_type) {
  ABSL_RETURN_IF_ERROR(
      CheckFipsCompatibility<RsaSsaPkcs1VerifyBoringSslImpl>());
  ABSL_RETURN_IF_ERROR(IsHashTypeSafeForSignature(hash_type));
  return EvpHashFromHashType(hash_type);
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewRsaSsaPkcs1VerifyBoringSsl(
    const RsaSsaPkcs1PublicKey& key) {
  RsaPublicKey public_key;
  public_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key.e =
      std::string(key.GetParameters().GetPublicExponent().GetValue());
  RsaSsaPkcs1Params params;
  switch (key.GetParameters().GetHashType()) {
    case RsaSsaPkcs1Parameters::HashType::kSha256:
      params.hash_type = subtle::SHA256;
      break;
    case RsaSsaPkcs1Parameters::HashType::kSha384:
      params.hash_type = subtle::SHA384;
      break;
    case RsaSsaPkcs1Parameters::HashType::kSha512:
      params.hash_type = subtle::SHA512;
      break;
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported hash:", key.GetParameters().GetHashType()));
  }
  const RsaSsaPkcs1Parameters::Variant variant =
      key.GetParameters().GetVariant();
  if (variant == RsaSsaPkcs1Parameters::Variant::kNoPrefix) {
    return NewRsaSsaPkcs1VerifyBoringSsl(public_key, params);
  }
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* sig_hash, GetSigHash(params.hash_type));
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<RSA> rsa, RsaPublicKeyToRsa(public_key));
  return std::make_unique<RsaSsaPkcs1VerifyWithPrefix>(
      std::move(rsa), sig_hash, key.GetOutputPrefix(),
      /*append_null_byte=*/variant == RsaSsaPkcs1Parameters::Variant::kLegacy);
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewRsaSsaPkcs1VerifyBoringSsl(
    const RsaPublicKey& pub_key, const RsaSsaPkcs1Params& params) {
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* sig_hash, GetSigHash(params.hash_type));
  // The RSA modulus and exponent are checked as part of the conversion to
  // SslUniquePtr<RSA>.
  ABSL_ASSIGN_OR_RETURN(SslUniquePtr<RSA> rsa, RsaPublicKeyToRsa(pub_key));
  return std::make_unique<RsaSsaPkcs1VerifyBoringSslImpl>(std::move(rsa),
                                                          sig_hash);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
