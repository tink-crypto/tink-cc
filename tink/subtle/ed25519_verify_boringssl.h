// Copyright 2019 Google LLC
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

#ifndef TINK_SUBTLE_ED25519_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_ED25519_VERIFY_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class Ed25519VerifyBoringSsl : public PublicKeyVerify {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      const Ed25519PublicKey& public_key);

  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      absl::string_view public_key) {
    return New(public_key, "", "");
  }

  // Verifies that 'signature' is a digital signature for 'data'.
  crypto::tink::util::Status Verify(absl::string_view signature,
                                    absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      absl::string_view public_key, absl::string_view output_prefix,
      absl::string_view message_suffix);

  explicit Ed25519VerifyBoringSsl(internal::SslUniquePtr<EVP_PKEY> public_key,
                                  absl::string_view output_prefix,
                                  absl::string_view message_suffix)
      : public_key_(std::move(public_key)),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  crypto::tink::util::Status VerifyWithoutPrefix(absl::string_view signature,
                                                 absl::string_view data) const;

  const internal::SslUniquePtr<EVP_PKEY> public_key_;
  const std::string output_prefix_;
  const std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ED25519_VERIFY_BORINGSSL_H_
