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

#ifndef TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_PARAMETERS_H_
#define TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_PARAMETERS_H_

#include <memory>

#include "absl/types/optional.h"
#include "tink/parameters.h"
#include "tink/streamingaead/streaming_aead_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes an AES-GCM-HKDF Streaming AEAD key (e.g., key attributes),
// excluding the randomly chosen key material.
class AesGcmHkdfStreamingParameters : public StreamingAeadParameters {
 public:
  enum class HashType : int {
    kSha1 = 1,
    kSha256 = 2,
    kSha512 = 3,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Creates AES-GCM-HKDF Streaming parameters instances.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty parameters builder.
    Builder() = default;

    Builder& SetKeySizeInBytes(int key_size);
    Builder& SetDerivedKeySizeInBytes(int derived_key_size);
    Builder& SetHashType(HashType hash_type);
    Builder& SetCiphertextSegmentSizeInBytes(int segment_size);

    // Creates AES-GCM-HKDF Streaming parameters object from this builder.
    absl::StatusOr<AesGcmHkdfStreamingParameters> Build();

   private:
    absl::optional<int> key_size_in_bytes_;
    absl::optional<int> derived_key_size_in_bytes_;
    absl::optional<HashType> hash_type_;
    absl::optional<int> segment_size_in_bytes_;
  };

  // Copyable and movable.
  AesGcmHkdfStreamingParameters(const AesGcmHkdfStreamingParameters& other) =
      default;
  AesGcmHkdfStreamingParameters& operator=(
      const AesGcmHkdfStreamingParameters& other) = default;
  AesGcmHkdfStreamingParameters(AesGcmHkdfStreamingParameters&& other) =
      default;
  AesGcmHkdfStreamingParameters& operator=(
      AesGcmHkdfStreamingParameters&& other) = default;

  int KeySizeInBytes() const { return key_size_in_bytes_; }
  int DerivedKeySizeInBytes() const { return derived_key_size_in_bytes_; }
  HashType GetHashType() const { return hash_type_; }
  int CiphertextSegmentSizeInBytes() const { return segment_size_in_bytes_; }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<AesGcmHkdfStreamingParameters>(*this);
  }

 private:
  explicit AesGcmHkdfStreamingParameters(int key_size_in_bytes,
                                         int derived_key_size_in_bytes,
                                         HashType hash_type,
                                         int segment_size_in_bytes)
      : key_size_in_bytes_(key_size_in_bytes),
        derived_key_size_in_bytes_(derived_key_size_in_bytes),
        hash_type_(hash_type),
        segment_size_in_bytes_(segment_size_in_bytes) {}

  int key_size_in_bytes_;
  int derived_key_size_in_bytes_;
  HashType hash_type_;
  int segment_size_in_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_AES_GCM_HKDF_STREAMING_PARAMETERS_H_
