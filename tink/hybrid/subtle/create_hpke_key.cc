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

#include "tink/hybrid/subtle/create_hpke_key.h"

#include <optional>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/internal/hpke_key_creator.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<HpkePrivateKey> CreateHpkePrivateKey(
    const HpkeParameters& parameters, std::optional<int> id_requirement) {
  ABSL_ASSIGN_OR_RETURN(HpkePrivateKey key, internal::CreatePrivateHpkeKey(
                                                parameters, id_requirement));
  return key;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
