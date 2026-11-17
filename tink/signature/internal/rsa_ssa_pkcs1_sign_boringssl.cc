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

#include "tink/signature/internal/rsa_ssa_pkcs1_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

class RsaSsaPkcs1SignBoringSslImpl : public PublicKeySign {
 public:
  static constexpr FipsCompatibility kFipsStatus =
      FipsCompatibility::kRequiresBoringCrypto;

  RsaSsaPkcs1SignBoringSslImpl(SslUniquePtr<RSA> private_key,
                               const EVP_MD* sig_hash,
                               absl::string_view output_prefix,
                               absl::string_view message_suffix)
      : private_key_(std::move(private_key)),
        sig_hash_(sig_hash),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

 private:
  absl::StatusOr<std::string> SignWithoutPrefix(absl::string_view data) const;

  const SslUniquePtr<RSA> private_key_;
  const EVP_MD* const sig_hash_;  // Owned by BoringSSL.
  const std::string output_prefix_;
  const std::string message_suffix_;
};

absl::StatusOr<std::string> RsaSsaPkcs1SignBoringSslImpl::SignWithoutPrefix(
    absl::string_view data) const {
  ABSL_ASSIGN_OR_RETURN(std::string digest,
                        ComputeHash({data, message_suffix_}, *sig_hash_));

  std::string signature;
  size_t signature_buffer_size = RSA_size(private_key_.get());
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  absl::Status s = CallWithCoreDumpProtection([&]() {
    unsigned int signature_length = 0;
    ScopedAssumeRegionCoreDumpSafe scope(&signature[0], signature_buffer_size);
    if (RSA_sign(/*hash_nid=*/EVP_MD_type(sig_hash_),
                 /*digest=*/reinterpret_cast<const uint8_t*>(digest.data()),
                 /*digest_len=*/digest.size(),
                 /*out=*/reinterpret_cast<uint8_t*>(&signature[0]),
                 /*out_len=*/&signature_length,
                 /*rsa=*/private_key_.get()) != 1) {
      // TODO(b/112581512): Decide if it's safe to propagate the BoringSSL
      // error. For now, just empty the error stack.
      GetSslErrors();
      return absl::Status(absl::StatusCode::kInternal, "Signing failed.");
    }
    DfsanClearLabel(&signature[0], signature_buffer_size);
    return absl::OkStatus();
  });
  if (!s.ok()) {
    return s;
  }
  return signature;
}

absl::StatusOr<std::string> RsaSsaPkcs1SignBoringSslImpl::Sign(
    absl::string_view data) const {
  absl::StatusOr<std::string> signature_without_prefix;
  signature_without_prefix = SignWithoutPrefix(data);
  if (!signature_without_prefix.ok()) {
    return signature_without_prefix.status();
  }
  if (output_prefix_.empty()) {
    return signature_without_prefix;
  }
  return absl::StrCat(output_prefix_, *signature_without_prefix);
}

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewRsaSsaPkcs1SignBoringSsl(
    const RsaPrivateKey& private_key, const RsaSsaPkcs1Params& params,
    absl::string_view output_prefix, absl::string_view message_suffix) {
  absl::Status status = CheckFipsCompatibility<RsaSsaPkcs1SignBoringSslImpl>();
  if (!status.ok()) {
    return status;
  }

  // Check if the hash type is safe to use.
  absl::Status is_safe = IsHashTypeSafeForSignature(params.hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }

  absl::StatusOr<const EVP_MD*> sig_hash =
      EvpHashFromHashType(params.hash_type);
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }

  // Check RSA's modulus.
  absl::StatusOr<SslUniquePtr<BIGNUM>> n = StringToBignum(private_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto modulus_status = ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }

  // The RSA modulus and exponent are checked as part of the conversion to
  // SslUniquePtr<RSA>.
  absl::StatusOr<SslUniquePtr<RSA>> rsa = RsaPrivateKeyToRsa(private_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  return std::make_unique<RsaSsaPkcs1SignBoringSslImpl>(
      *std::move(rsa), *sig_hash, output_prefix, message_suffix);
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewRsaSsaPkcs1SignBoringSsl(
    const RsaSsaPkcs1PrivateKey& key) {
  RsaPrivateKey private_key;
  private_key.n = std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  private_key.e = std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  private_key.d =
      key.GetPrivateExponentData().Get(InsecureSecretKeyAccess::Get());
  private_key.p = key.GetPrimePData(GetPartialKeyAccess())
                      .Get(InsecureSecretKeyAccess::Get());
  private_key.q = key.GetPrimeQData(GetPartialKeyAccess())
                      .Get(InsecureSecretKeyAccess::Get());
  private_key.dp =
      key.GetPrimeExponentPData().Get(InsecureSecretKeyAccess::Get());
  private_key.dq =
      key.GetPrimeExponentQData().Get(InsecureSecretKeyAccess::Get());
  private_key.crt =
      key.GetCrtCoefficientData().Get(InsecureSecretKeyAccess::Get());
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
  return NewRsaSsaPkcs1SignBoringSsl(
      private_key, params, key.GetOutputPrefix(),
      key.GetParameters().GetVariant() ==
              RsaSsaPkcs1Parameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
