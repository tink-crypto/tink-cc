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

#ifndef TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_PARAMETERS_H_
#define TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_PARAMETERS_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead/aead_parameters.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of a LegacyKmsEnvelopeAeadKey.
//
// Usage of this key type is not recommended. Instead, we recommend to
// implement the idea of this class manually, i.e., create a remote Aead object
// for your KMS with an appropriate Tink extension (typically using a subclass
// of `KmsClient`), and then create an envelope AEAD with
// `KmsEnvelopeAead::New`.
//
// Known Issues:
//  1. Global registration:
//    If a user uses a `LegacyKmsEnvelopeAeadKey`, when
//    the corresponding `Aead` is created, Tink looks up the `KmsClient` in a
//    global registry. This registry needs to store all the credentials and all
//    the information. This is inappropriate in many situations.
//
//   2. Ciphertext format:
//    The ciphertext format does not encode the key type of the key used. This
//    can lead to unexpected results if a user changes the `dekParameters` or
//    the `dekParsingStrategy` for the same remote key. In more details, the
//    ciphertext contains a Tink key proto of newly generated key, but not the
//    type URL. This means that if a user reuses the same remote Key with a
//    different key type, it will be parsed with the wrong one.
//
//    Also, Tink does not compare the parameters of the parsed key with the
//    parameters specified in 'dekParameters`. For example, if the
//    `dekParameters` is specified as AES_128_GCM in one binary, and AES_256_GCM
//    in another binary, communication between the binaries succeeds in both
//    directions.
//
//  3. Ciphertext malleability:
//   Some KMS have malleable ciphertexts. This means that the Aeads
//   corresponding to these keys may be malleable. See
//   https://developers.google.com/tink/issues/envelope-aead-malleability
class LegacyKmsEnvelopeAeadParameters : public AeadParameters {
 public:
  // Description of the output prefix prepended to the ciphertext.
  enum class Variant : int {
    // Prepends '0x01<big endian key id>' to the ciphertext.
    kTink = 1,
    // Does not prepend any prefix (i.e., keys must have no ID requirement).
    kNoPrefix = 2,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Specifies how the DEKs in received ciphertexts are parsed.
  enum class DekParsingStrategy : int {
    // When parsing, assume that the ciphertext was encrypted with AES-GCM.
    kAssumeAesGcm = 1,
    // When parsing, assume that the ciphertext was encrypted with
    // XChaCha20-Poly1305.
    kAssumeXChaCha20Poly1305 = 2,
    // When parsing, assume that the ciphertext was encrypted with AES-GCM-SIV.
    kAssumeAesGcmSiv = 3,
    // When parsing, assume that the ciphertext was encrypted with AES-CTR-HMAC.
    kAssumeAesCtrHmac = 4,
    // When parsing, assume that the ciphertext was encrypted with AES-EAX.
    kAssumeAesEax = 5,
    // Added to guard from failures that may be caused by future expansions.
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  LegacyKmsEnvelopeAeadParameters(
      const LegacyKmsEnvelopeAeadParameters& other) = default;
  LegacyKmsEnvelopeAeadParameters& operator=(
      const LegacyKmsEnvelopeAeadParameters& other) = default;
  LegacyKmsEnvelopeAeadParameters(LegacyKmsEnvelopeAeadParameters&& other) =
      default;
  LegacyKmsEnvelopeAeadParameters& operator=(
      LegacyKmsEnvelopeAeadParameters&& other) = default;

  static util::StatusOr<LegacyKmsEnvelopeAeadParameters> Create(
      absl::string_view key_uri, Variant variant,
      DekParsingStrategy dek_parsing_strategy,
      const AeadParameters& dek_parameters);

  const std::string& GetKeyUri() const { return key_uri_; }

  Variant GetVariant() const { return variant_; }

  // Returns strategy used when parsing encrypted keys.
  DekParsingStrategy GetDekParsingStrategy() const {
    return dek_parsing_strategy_;
  }

  const AeadParameters& GetDekParameters() const { return *dek_parameters_; }

  bool HasIdRequirement() const override {
    return variant_ != Variant::kNoPrefix;
  }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<LegacyKmsEnvelopeAeadParameters>(*this);
  }

 private:
  explicit LegacyKmsEnvelopeAeadParameters(
      absl::string_view key_uri, Variant variant,
      DekParsingStrategy dek_parsing_strategy,
      std::unique_ptr<const AeadParameters> dek_parameters)
      : key_uri_(key_uri),
        variant_(variant),
        dek_parsing_strategy_(dek_parsing_strategy),
        dek_parameters_(std::move(dek_parameters)) {}

  std::string key_uri_;
  Variant variant_;
  DekParsingStrategy dek_parsing_strategy_;
  std::shared_ptr<const AeadParameters> dek_parameters_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_LEGACY_KMS_ENVELOPE_AEAD_PARAMETERS_H_
