// Copyright 2024 Google LLC
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

#ifndef TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_KEY_H_
#define TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_key.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents an Envelope AEAD that is backed by a KMS.
//
// Usage of this key type is not recommended. Instead, we recommend to
// implement the idea of this class manually, i.e. create a remote Aead object
// for your KMS with an appropriate Tink extension (typically using a subclass
// of `KmsClient`), and then create an envelope AEAD with
// `KmsEnvelopeAead::New`.
//
// See `LegacyKmsEnvelopeAeadParameters` for known issues.
class LegacyKmsEnvelopeAeadKey : public AeadKey {
 public:
  // Copyable and movable.
  LegacyKmsEnvelopeAeadKey(const LegacyKmsEnvelopeAeadKey& other) = default;
  LegacyKmsEnvelopeAeadKey& operator=(const LegacyKmsEnvelopeAeadKey& other) =
      default;
  LegacyKmsEnvelopeAeadKey(LegacyKmsEnvelopeAeadKey&& other) = default;
  LegacyKmsEnvelopeAeadKey& operator=(LegacyKmsEnvelopeAeadKey&& other) =
      default;

  static absl::StatusOr<LegacyKmsEnvelopeAeadKey> Create(
      const LegacyKmsEnvelopeAeadParameters& parameters,
      absl::optional<int> id_requirement);

  const LegacyKmsEnvelopeAeadParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<LegacyKmsEnvelopeAeadKey>(*this);
  }

 private:
  LegacyKmsEnvelopeAeadKey(const LegacyKmsEnvelopeAeadParameters& parameters,
                           absl::optional<int> id_requirement,
                           std::string output_prefix)
      : parameters_(parameters),
        id_requirement_(id_requirement),
        output_prefix_(std::move(output_prefix)) {}

  LegacyKmsEnvelopeAeadParameters parameters_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_KEY_H_
