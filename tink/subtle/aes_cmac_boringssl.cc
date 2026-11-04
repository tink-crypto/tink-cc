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

#include "tink/subtle/aes_cmac_boringssl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/subtle/create_aes_cmac_mac.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
absl::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(SecretData key,
                                                           uint32_t tag_size) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<AesCmacBoringSsl>());
  ABSL_ASSIGN_OR_RETURN(
      AesCmacParameters parameters,
      AesCmacParameters::Create(key.size(), tag_size,
                                AesCmacParameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      AesCmacKey aes_cmac_key,
      AesCmacKey::Create(
          parameters,
          RestrictedData(std::move(key), InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return CreateAesCmacMac(aes_cmac_key);
}

// static
absl::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(
    const AesCmacKey& key) {
  return CreateAesCmacMac(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
