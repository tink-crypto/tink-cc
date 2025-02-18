// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/prf/aes_cmac_prf_key.h"

#include <utility>

#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<AesCmacPrfKey> AesCmacPrfKey::Create(
    RestrictedData key_bytes, PartialKeyAccessToken token) {
  absl::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(key_bytes.size());
  if (!parameters.ok()) {
    return parameters.status();
  }
  return AesCmacPrfKey(std::move(*parameters), std::move(key_bytes));
}

bool AesCmacPrfKey::operator==(const Key& other) const {
  const AesCmacPrfKey* that = dynamic_cast<const AesCmacPrfKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  return key_bytes_ == that->key_bytes_;
}

}  // namespace tink
}  // namespace crypto
