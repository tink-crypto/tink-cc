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

#include "tink/subtle/aes_gcm_boringssl.h"

#include <memory>
#include <optional>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/subtle/create_aes_gcm_aead.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Aead>> AesGcmBoringSsl::New(
    const AesGcmKey& key) {
  return CreateAesGcmAead(key);
}

absl::StatusOr<std::unique_ptr<Aead>> AesGcmBoringSsl::New(
    const SecretData& key) {
  // CreateAesGcmAead already checks FIPS compatibility.
  ABSL_ASSIGN_OR_RETURN(AesGcmParameters parameters,
                        AesGcmParameters::Builder()
                            .SetKeySizeInBytes(key.size())
                            .SetIvSizeInBytes(12)
                            .SetTagSizeInBytes(16)
                            .SetVariant(AesGcmParameters::Variant::kNoPrefix)
                            .Build());
  ABSL_ASSIGN_OR_RETURN(
      AesGcmKey aes_gcm_key,
      AesGcmKey::Create(
          parameters, RestrictedData(key, InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return CreateAesGcmAead(aes_gcm_key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
