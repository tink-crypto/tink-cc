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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PUBLIC_KEY_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PUBLIC_KEY_H_

#include <string>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/kem/kem_public_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Representation of the encapsulation function for the ML-KEM key encapsulation
// mechanism primitive.
class MlKemPublicKey : public KemPublicKey {
 public:
  // Copyable and movable.
  MlKemPublicKey(const MlKemPublicKey& other) = default;
  MlKemPublicKey& operator=(const MlKemPublicKey& other) = default;
  MlKemPublicKey(MlKemPublicKey&& other) = default;
  MlKemPublicKey& operator=(MlKemPublicKey&& other) = default;

  // Creates a new ML-KEM public key from `public_key_bytes`. If the
  // `parameters` specify a variant that uses a prefix, then `id_requirement` is
  // used to compute this prefix.
  static util::StatusOr<MlKemPublicKey> Create(
      const MlKemParameters& parameters, absl::string_view public_key_bytes,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  absl::string_view GetPublicKeyBytes(PartialKeyAccessToken token) const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return public_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return output_prefix_;
  }

  const MlKemParameters& GetParameters() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return parameters_;
  }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  explicit MlKemPublicKey(const MlKemParameters& parameters,
                          absl::string_view public_key_bytes,
                          absl::optional<int> id_requirement,
                          absl::string_view output_prefix)
      : parameters_(parameters),
        public_key_bytes_(public_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  MlKemParameters parameters_;
  std::string public_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_ML_KEM_PUBLIC_KEY_H_
