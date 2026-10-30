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

#include "tink/prf/subtle/create_aes_cmac_prf.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/internal/stateful_cmac_boringssl.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/prf_set.h"
#include "tink/restricted_data.h"
#include "tink/subtle/prf/prf_set_util.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Prf>> CreateAesCmacPrf(
    const AesCmacPrfKey& key) {
  ABSL_RETURN_IF_ERROR(
      internal::ChecksFipsCompatibility(internal::FipsCompatibility::kNotFips));
  if (key.GetParameters().KeySizeInBytes() != 16 &&
      key.GetParameters().KeySizeInBytes() != 32) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Key size must be either 16 or 32 bytes.");
  }
  return CreatePrfFromStatefulMacFactory(
      std::make_unique<internal::StatefulCmacBoringSslFactory>(
          /*tag_size=*/16, key.GetKeyBytes(GetPartialKeyAccess())
                               .Get(InsecureSecretKeyAccess::Get())));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
