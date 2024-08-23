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

#include "tink/prf/hmac_prf_key.h"

#include "absl/status/status.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<HmacPrfKey> HmacPrfKey::Create(
    const HmacPrfParameters& parameters, const RestrictedData& key_bytes,
    PartialKeyAccessToken token) {
  if (parameters.KeySizeInBytes() != key_bytes.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size does not match HMAC-PRF parameters");
  }

  return HmacPrfKey(parameters, key_bytes);
}

bool HmacPrfKey::operator==(const Key& other) const {
  const HmacPrfKey* that = dynamic_cast<const HmacPrfKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return GetParameters() == that->GetParameters() &&
         key_bytes_ == that->key_bytes_;
}

}  // namespace tink
}  // namespace crypto
