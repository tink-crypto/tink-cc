// Copyright 2026 Google LLC
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

#ifndef TINK_SIGNATURE_COMPOSITE_ML_DSA_PUBLIC_KEY_H_
#define TINK_SIGNATURE_COMPOSITE_ML_DSA_PUBLIC_KEY_H_

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/signature_public_key.h"

namespace crypto {
namespace tink {

class CompositeMlDsaPublicKey final : public SignaturePublicKey {
 public:
  // Copyable and movable.
  CompositeMlDsaPublicKey(const CompositeMlDsaPublicKey& other);
  CompositeMlDsaPublicKey& operator=(const CompositeMlDsaPublicKey& other);
  CompositeMlDsaPublicKey(CompositeMlDsaPublicKey&& other) = default;
  CompositeMlDsaPublicKey& operator=(CompositeMlDsaPublicKey&& other) = default;

  static absl::StatusOr<CompositeMlDsaPublicKey> Create(
      const CompositeMlDsaParameters& parameters,
      const MlDsaPublicKey& ml_dsa_public_key,
      std::unique_ptr<SignaturePublicKey> classical_public_key,
      absl::optional<int> id_requirement,
      PartialKeyAccessToken token);

  const CompositeMlDsaParameters& GetParameters() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return parameters_;
  }
  const MlDsaPublicKey& GetMlDsaPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return ml_dsa_public_key_;
  }
  const SignaturePublicKey& GetClassicalPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return *classical_public_key_;
  }
  absl::optional<int32_t> GetIdRequirement() const override {
    return id_requirement_;
  }
  absl::string_view GetOutputPrefix() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return output_prefix_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override;

 private:
  explicit CompositeMlDsaPublicKey(
      const CompositeMlDsaParameters& parameters,
      const MlDsaPublicKey& ml_dsa_public_key,
      std::unique_ptr<SignaturePublicKey> classical_public_key,
      absl::optional<int> id_requirement,
      absl::string_view output_prefix)
      : parameters_(parameters),
        ml_dsa_public_key_(ml_dsa_public_key),
        classical_public_key_(std::move(classical_public_key)),
        id_requirement_(id_requirement),
        output_prefix_(output_prefix) {}

  CompositeMlDsaParameters parameters_;
  MlDsaPublicKey ml_dsa_public_key_;
  std::unique_ptr<SignaturePublicKey> classical_public_key_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_COMPOSITE_MLDSA_PUBLIC_KEY_H_
