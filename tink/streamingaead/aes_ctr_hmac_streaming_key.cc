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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"

#include "absl/status/status.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<AesCtrHmacStreamingKey> AesCtrHmacStreamingKey::Create(
    const AesCtrHmacStreamingParameters& parameters,
    const RestrictedData& initial_key_material, PartialKeyAccessToken token) {
  if (parameters.KeySizeInBytes() != initial_key_material.size()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Key size does not match AES-CTR-HMAC Streaming parameters");
  }
  return AesCtrHmacStreamingKey(parameters, initial_key_material);
}

bool AesCtrHmacStreamingKey::operator==(const Key& other) const {
  const AesCtrHmacStreamingKey* that =
      dynamic_cast<const AesCtrHmacStreamingKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  return initial_key_material_ == that->initial_key_material_;
}

}  // namespace tink
}  // namespace crypto
