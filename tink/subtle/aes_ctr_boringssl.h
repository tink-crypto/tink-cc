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

#ifndef TINK_SUBTLE_AES_CTR_BORINGSSL_H_
#define TINK_SUBTLE_AES_CTR_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"
#include "tink/subtle/ind_cpa_cipher.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesCtrBoringSsl : public IndCpaCipher {
 public:
  static absl::StatusOr<std::unique_ptr<IndCpaCipher>> New(SecretData key,
                                                           int iv_size);

  absl::StatusOr<std::string> Encrypt(
      absl::string_view plaintext) const override;

  absl::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  static constexpr int kMinIvSizeInBytes = 12;
  static constexpr int kBlockSize = 16;

  AesCtrBoringSsl(SecretData key, int iv_size, const EVP_CIPHER* cipher)
      : key_(std::move(key)), iv_size_(iv_size), cipher_(cipher) {}

  const SecretData key_;
  const int iv_size_;
  // cipher_ is a singleton owned by BoringSsl.
  const EVP_CIPHER *cipher_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CTR_BORINGSSL_H_
