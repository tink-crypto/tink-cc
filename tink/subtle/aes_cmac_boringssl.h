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

#ifndef TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
#define TINK_SUBTLE_AES_CMAC_BORINGSSL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesCmacBoringSsl : public Mac {
 public:
  static absl::StatusOr<std::unique_ptr<Mac>> New(SecretData key,
                                                  uint32_t tag_size);

  static absl::StatusOr<std::unique_ptr<Mac>> New(const AesCmacKey& key);

  // Computes and returns the CMAC for 'data'.
  absl::StatusOr<std::string> ComputeMac(absl::string_view data) const override;

  // Verifies if 'mac' is a correct CMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  absl::Status VerifyMac(absl::string_view mac,
                         absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  // Computes and returns the CMAC for 'data'.
  absl::StatusOr<std::string> ComputeMacNoPrefix(
      absl::string_view data) const;

  // Verifies if 'mac' is a correct CMAC for 'data'.
  // Returns Status::OK if 'mac' is correct, and a non-OK-Status otherwise.
  absl::Status VerifyMacNoPrefix(absl::string_view mac,
                             absl::string_view data) const;

  AesCmacBoringSsl(SecretData key, uint32_t tag_size,
                   absl::string_view output_prefix,
                   absl::string_view message_suffix)
      : key_(std::move(key)),
        tag_size_(tag_size),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  const SecretData key_;
  const uint32_t tag_size_;
  std::string output_prefix_;
  std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
