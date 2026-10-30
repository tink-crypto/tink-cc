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

#include "tink/subtle/aes_siv_boringssl.h"

#include <memory>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_boringssl.h"
#include "tink/deterministic_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
absl::StatusOr<std::unique_ptr<DeterministicAead>> AesSivBoringSsl::New(
    const SecretData& key) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<AesSivBoringSsl>());
  if (key.size() != 64) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid key size");
  }
  ABSL_ASSIGN_OR_RETURN(AesSivParameters parameters,
                        AesSivParameters::Create(
                            key.size(), AesSivParameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      AesSivKey aes_siv_key,
      AesSivKey::Create(
          parameters, RestrictedData(key, InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return internal::NewAesSivBoringSsl(aes_siv_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
