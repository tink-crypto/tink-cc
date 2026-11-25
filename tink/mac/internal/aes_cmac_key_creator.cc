// Copyright 2026 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/mac/internal/aes_cmac_key_creator.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<Key>> CreateAesCmacKey(
    const AesCmacParameters& parameters, std::optional<int> id_requirement) {
  RestrictedData key_bytes(parameters.KeySizeInBytes());
  ABSL_ASSIGN_OR_RETURN(
      AesCmacKey key,
      AesCmacKey::Create(parameters, std::move(key_bytes), id_requirement,
                         GetPartialKeyAccess()));
  return std::make_unique<AesCmacKey>(std::move(key));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
