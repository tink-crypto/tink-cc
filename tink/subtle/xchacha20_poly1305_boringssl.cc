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

#include "tink/subtle/xchacha20_poly1305_boringssl.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/internal/zero_copy_xchacha20_poly1305_boringssl.h"
#include "tink/internal/fips_utils.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Aead>> XChacha20Poly1305BoringSsl::New(
    SecretData key) {
  auto status = internal::CheckFipsCompatibility<XChacha20Poly1305BoringSsl>();
  if (!status.ok()) {
    return status;
  }
  absl::StatusOr<std::unique_ptr<internal::ZeroCopyAead>> aead =
      internal::ZeroCopyXChacha20Poly1305BoringSsl::New(std::move(key));
  if (!aead.ok()) {
    return aead.status();
  }
  std::unique_ptr<Aead> aead_impl =
      absl::WrapUnique(new XChacha20Poly1305BoringSsl(*std::move(aead)));
  return std::move(aead_impl);
}

XChacha20Poly1305BoringSsl::XChacha20Poly1305BoringSsl(
    std::unique_ptr<internal::ZeroCopyAead> aead)
    : AeadFromZeroCopy(std::move(aead)) {}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
