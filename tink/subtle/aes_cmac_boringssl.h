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

class AesCmacBoringSsl {
 public:
  // Creates a raw AES-CMAC `Mac` (without any output prefix).
  // Supported key sizes are 16 and 32 bytes, and supported tag sizes are 10 to
  // 16 bytes.
  //
  // Prefer `CreateAesCmacMac`, which takes an `AesCmacKey` and also supports
  // key variants with output prefixes (`kTink`, `kCrunchy`, `kLegacy`).
  static absl::StatusOr<std::unique_ptr<Mac>> New(SecretData key,
                                                  uint32_t tag_size);

  static absl::StatusOr<std::unique_ptr<Mac>> New(const AesCmacKey& key);

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  AesCmacBoringSsl() = delete;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CMAC_BORINGSSL_H_
