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

#ifndef TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_H_
#define TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/streaming_aead_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a Streaming AEAD that uses AES-GCM-HKDF Streaming.
class AesGcmHkdfStreamingKey final : public StreamingAeadKey {
 public:
  // Copyable and movable.
  AesGcmHkdfStreamingKey(const AesGcmHkdfStreamingKey& other) = default;
  AesGcmHkdfStreamingKey& operator=(const AesGcmHkdfStreamingKey& other) =
      default;
  AesGcmHkdfStreamingKey(AesGcmHkdfStreamingKey&& other) = default;
  AesGcmHkdfStreamingKey& operator=(AesGcmHkdfStreamingKey&& other) = default;

  // Creates a new AES-GCM-HKDF Streaming key.
  static absl::StatusOr<AesGcmHkdfStreamingKey> Create(
      const AesGcmHkdfStreamingParameters& parameters,
      const RestrictedData& initial_key_material, PartialKeyAccessToken token);

  const RestrictedData& GetInitialKeyMaterial(
      PartialKeyAccessToken token) const {
    return initial_key_material_;
  }

  const AesGcmHkdfStreamingParameters& GetParameters() const override {
    return parameters_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<AesGcmHkdfStreamingKey>(*this);
  }

 private:
  AesGcmHkdfStreamingKey(const AesGcmHkdfStreamingParameters& parameters,
                         const RestrictedData& initial_key_material)
      : parameters_(parameters), initial_key_material_(initial_key_material) {}

  AesGcmHkdfStreamingParameters parameters_;
  RestrictedData initial_key_material_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_KEY_H_
