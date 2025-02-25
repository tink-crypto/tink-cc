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

#ifndef TINK_SUBTLE_RSA_SSA_PKCS1_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_RSA_SSA_PKCS1_VERIFY_BORINGSSL_H_

#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// RSA SSA (Signature Schemes with Appendix) using PKCS1 (Public-Key
// Cryptography Standards) encoding is defined at
// https://tools.ietf.org/html/rfc8017#section-8.2). This implemention uses
// BoringSSL for the underlying cryptographic operations.
class RsaSsaPkcs1VerifyBoringSsl : public PublicKeyVerify {
 public:
  static absl::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>> New(
      const internal::RsaPublicKey& pub_key,
      const internal::RsaSsaPkcs1Params& params);

  static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      const RsaSsaPkcs1PublicKey& key);

  // Verifies that 'signature' is a digital signature for 'data'.
  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  ~RsaSsaPkcs1VerifyBoringSsl() override = default;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  // To reach 128-bit security strength, RSA's modulus must be at least 3072-bit
  // while 2048-bit RSA key only has 112-bit security. Nevertheless, a 2048-bit
  // RSA key is considered safe by NIST until 2030 (see
  // https://www.keylength.com/en/4/).
  static constexpr size_t kMinModulusSizeInBits = 2048;

  static absl::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>> New(
      const internal::RsaPublicKey& pub_key,
      const internal::RsaSsaPkcs1Params& params,
      absl::string_view output_prefix, absl::string_view message_suffix);

  RsaSsaPkcs1VerifyBoringSsl(internal::SslUniquePtr<RSA> rsa,
                             const EVP_MD* sig_hash,
                             absl::string_view output_prefix,
                             absl::string_view message_suffix)
      : rsa_(std::move(rsa)),
        sig_hash_(sig_hash),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::Status VerifyWithoutPrefix(absl::string_view signature,
                                   absl::string_view data) const;

  const internal::SslUniquePtr<RSA> rsa_;
  const EVP_MD* const sig_hash_;  // Owned by BoringSSL.
  const std::string output_prefix_;
  const std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RSA_SSA_PKCS1_VERIFY_BORINGSSL_H_
