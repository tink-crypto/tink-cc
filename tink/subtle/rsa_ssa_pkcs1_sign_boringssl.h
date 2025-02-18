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

#ifndef TINK_SUBTLE_RSA_SSA_PKCS1_SIGN_BORINGSSL_H_
#define TINK_SUBTLE_RSA_SSA_PKCS1_SIGN_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/ec.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// The RSA SSA (Signature Schemes with Appendix) using PKCS1 (Public-Key
// Cryptography Standards) encoding is defined at
// https://tools.ietf.org/html/rfc8017#section-8.2). This implemention uses
// Boring SSL for the underlying cryptographic operations.
class RsaSsaPkcs1SignBoringSsl : public PublicKeySign {
 public:
  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const internal::RsaPrivateKey& private_key,
      const internal::RsaSsaPkcs1Params& params);

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const RsaSsaPkcs1PrivateKey& key);

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

  ~RsaSsaPkcs1SignBoringSsl() override = default;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const internal::RsaPrivateKey& private_key,
      const internal::RsaSsaPkcs1Params& params,
      absl::string_view output_prefix, absl::string_view message_suffix);

  RsaSsaPkcs1SignBoringSsl(internal::SslUniquePtr<RSA> private_key,
                           const EVP_MD* sig_hash,
                           absl::string_view output_prefix,
                           absl::string_view message_suffix)
      : private_key_(std::move(private_key)),
        sig_hash_(sig_hash),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> SignWithoutPrefix(absl::string_view data) const;

  const internal::SslUniquePtr<RSA> private_key_;
  const EVP_MD* const sig_hash_;  // Owned by BoringSSL.
  const std::string output_prefix_;
  const std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RSA_SSA_PKCS1_SIGN_BORINGSSL_H_
