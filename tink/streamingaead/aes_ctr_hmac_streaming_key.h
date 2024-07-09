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

#ifndef TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_H_
#define TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_H_

#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/streaming_aead_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a Streaming AEAD that uses AES-CTR-HMAC Streaming.
class AesCtrHmacStreamingKey : public StreamingAeadKey {
 public:
  // Copyable and movable.
  AesCtrHmacStreamingKey(const AesCtrHmacStreamingKey& other) = default;
  AesCtrHmacStreamingKey& operator=(const AesCtrHmacStreamingKey& other) =
      default;
  AesCtrHmacStreamingKey(AesCtrHmacStreamingKey&& other) = default;
  AesCtrHmacStreamingKey& operator=(AesCtrHmacStreamingKey&& other) = default;

  // Creates a new AES-CTR-HMAC Streaming key.
  static util::StatusOr<AesCtrHmacStreamingKey> Create(
      const AesCtrHmacStreamingParameters& parameters,
      const RestrictedData& initial_key_material, PartialKeyAccessToken token);

  // Returns the initial key material for AES-CTR-HMAC Streaming.
  const RestrictedData& GetInitialKeyMaterial(
      PartialKeyAccessToken token) const {
    return initial_key_material_;
  }

  const AesCtrHmacStreamingParameters& GetParameters() const override {
    return parameters_;
  }

  bool operator==(const Key& other) const override;

 private:
  AesCtrHmacStreamingKey(const AesCtrHmacStreamingParameters& parameters,
                         const RestrictedData& initial_key_material)
      : parameters_(parameters), initial_key_material_(initial_key_material) {}

  AesCtrHmacStreamingParameters parameters_;
  RestrictedData initial_key_material_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_AES_CTR_HMAC_STREAMING_KEY_H_
