// Copyright 2018 Google LLC
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

#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"

#include <cstddef>
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
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

using ::crypto::tink::util::SecretDataFromStringView;

util::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPkcs1SignBoringSsl::New(
    const RsaSsaPkcs1PrivateKey& key) {
  internal::RsaPrivateKey private_key;
  private_key.n = std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  private_key.e = std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  private_key.d = SecretDataFromStringView(
      key.GetPrivateExponent().GetSecret(InsecureSecretKeyAccess::Get()));
  private_key.p =
      SecretDataFromStringView(key.GetPrimeP(GetPartialKeyAccess())
                                   .GetSecret(InsecureSecretKeyAccess::Get()));
  private_key.q =
      SecretDataFromStringView(key.GetPrimeQ(GetPartialKeyAccess())
                                   .GetSecret(InsecureSecretKeyAccess::Get()));
  private_key.dp = SecretDataFromStringView(
      key.GetPrimeExponentP().GetSecret(InsecureSecretKeyAccess::Get()));
  private_key.dq = SecretDataFromStringView(
      key.GetPrimeExponentQ().GetSecret(InsecureSecretKeyAccess::Get()));
  private_key.crt = SecretDataFromStringView(
      key.GetCrtCoefficient().GetSecret(InsecureSecretKeyAccess::Get()));
  internal::RsaSsaPkcs1Params params;
  switch (key.GetParameters().GetHashType()) {
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha256:
      params.hash_type = SHA256;
      break;
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha384:
      params.hash_type = SHA384;
      break;
    case crypto::tink::RsaSsaPkcs1Parameters::HashType::kSha512:
      params.hash_type = SHA512;
      break;
    default:
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported hash:", key.GetParameters().GetHashType()));
  }
  return New(private_key, params, key.GetOutputPrefix(),
             key.GetParameters().GetVariant() ==
                     RsaSsaPkcs1Parameters::Variant::kLegacy
                 ? std::string(1, 0)
                 : "");
}

util::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPkcs1SignBoringSsl::New(
    const internal::RsaPrivateKey& private_key,
    const internal::RsaSsaPkcs1Params& params) {
  return New(private_key, params, "", "");
}

util::StatusOr<std::unique_ptr<PublicKeySign>> RsaSsaPkcs1SignBoringSsl::New(
    const internal::RsaPrivateKey& private_key,
    const internal::RsaSsaPkcs1Params& params, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  util::Status status =
      internal::CheckFipsCompatibility<RsaSsaPkcs1SignBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  // Check if the hash type is safe to use.
  util::Status is_safe = internal::IsHashTypeSafeForSignature(params.hash_type);
  if (!is_safe.ok()) {
    return is_safe;
  }

  util::StatusOr<const EVP_MD*> sig_hash =
      internal::EvpHashFromHashType(params.hash_type);
  if (!sig_hash.ok()) {
    return sig_hash.status();
  }

  // Check RSA's modulus.
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(private_key.n);
  if (!n.ok()) {
    return n.status();
  }
  auto modulus_status = internal::ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }

  // The RSA modulus and exponent are checked as part of the conversion to
  // internal::SslUniquePtr<RSA>.
  util::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      internal::RsaPrivateKeyToRsa(private_key);
  if (!rsa.ok()) {
    return rsa.status();
  }

  return {absl::WrapUnique(new RsaSsaPkcs1SignBoringSsl(
      *std::move(rsa), *sig_hash, output_prefix, message_suffix))};
}

util::StatusOr<std::string> RsaSsaPkcs1SignBoringSsl::SignWithoutPrefix(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);
  util::StatusOr<std::string> digest = internal::ComputeHash(data, *sig_hash_);
  if (!digest.ok()) {
    return digest.status();
  }

  std::string signature;
  size_t signature_buffer_size = RSA_size(private_key_.get());
  ResizeStringUninitialized(&signature, signature_buffer_size);

  util::Status s = internal::CallWithCoreDumpProtection([&]() {
    unsigned int signature_length = 0;
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    if (RSA_sign(/*hash_nid=*/EVP_MD_type(sig_hash_),
                 /*digest=*/reinterpret_cast<const uint8_t*>(digest->data()),
                 /*digest_len=*/digest->size(),
                 /*out=*/reinterpret_cast<uint8_t*>(&signature[0]),
                 /*out_len=*/&signature_length,
                 /*rsa=*/private_key_.get()) != 1) {
      // TODO(b/112581512): Decide if it's safe to propagate the BoringSSL
      // error. For now, just empty the error stack.
      internal::GetSslErrors();
      return util::Status(absl::StatusCode::kInternal, "Signing failed.");
    }
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
    signature.resize(signature_length);
    return util::OkStatus();
  });
  if (!s.ok()) {
    return s;
  }
  return signature;
}

util::StatusOr<std::string> RsaSsaPkcs1SignBoringSsl::Sign(
    absl::string_view data) const {
  util::StatusOr<std::string> signature_without_prefix_;
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
