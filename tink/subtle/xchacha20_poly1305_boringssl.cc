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
#include <optional>
#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/subtle/create_xchacha20_poly1305_aead.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Aead>> XChacha20Poly1305BoringSsl::New(
    const XChaCha20Poly1305Key& key) {
  return CreateXChaCha20Poly1305Aead(key);
}

absl::StatusOr<std::unique_ptr<Aead>> XChacha20Poly1305BoringSsl::New(
    SecretData key) {
  // CreateXChaCha20Poly1305Aead already checks FIPS compatibility.
  ABSL_ASSIGN_OR_RETURN(
      XChaCha20Poly1305Key xchacha20_poly1305_key,
      XChaCha20Poly1305Key::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix,
          RestrictedData(std::move(key), InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return CreateXChaCha20Poly1305Aead(xchacha20_poly1305_key);
}

XChacha20Poly1305BoringSsl::XChacha20Poly1305BoringSsl(
    std::unique_ptr<internal::ZeroCopyAead> aead)
    : AeadFromZeroCopy(std::move(aead)) {}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
