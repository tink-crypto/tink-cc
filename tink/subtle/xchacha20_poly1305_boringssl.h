// Copyright 2018 Google Inc.
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

#ifndef TINK_SUBTLE_XCHACHA20_POLY1305_BORINGSSL_H_
#define TINK_SUBTLE_XCHACHA20_POLY1305_BORINGSSL_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

class XChacha20Poly1305BoringSsl
    : public internal::AeadFromZeroCopy /* implements `Aead` */ {
 public:
  // Constructs a new Aead cipher for XChacha20-Poly1305.
  // Currently supported key size is 256 bits.
  // Currently supported nonce size is 24 bytes.
  // The tag size is fixed to 16 bytes.
  static absl::StatusOr<std::unique_ptr<Aead>> New(SecretData key);

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  explicit XChacha20Poly1305BoringSsl(
      std::unique_ptr<internal::ZeroCopyAead> aead);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_XCHACHA20_POLY1305_BORINGSSL_H_
