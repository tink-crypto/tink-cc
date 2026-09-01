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

#ifndef TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_
#define TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class Ed25519SignBoringSsl : public PublicKeySign {
 public:
  // Creates a new PublicKeySign. private-key must be the concatenation of the
  // Ed25519 private key material with the public key material (following the
  // OpenSSL/BoringSSL API).
  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      SecretData private_key) {
    return New(private_key, "", "");
  }

  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const Ed25519PrivateKey& key);

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override = 0;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  ~Ed25519SignBoringSsl() override = default;

 protected:
  Ed25519SignBoringSsl() = default;

 private:
  static absl::StatusOr<std::unique_ptr<PublicKeySign>> New(
      SecretData private_key, absl::string_view output_prefix,
      absl::string_view message_suffix);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ED25519_SIGN_BORINGSSL_H_
