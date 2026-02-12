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

#ifndef TINK_SIGNATURE_COMPOSITE_ML_DSA_PRIVATE_KEY_H_
#define TINK_SIGNATURE_COMPOSITE_ML_DSA_PRIVATE_KEY_H_

#include <memory>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_public_key.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {

class CompositeMlDsaPrivateKey final : public SignaturePrivateKey {
 public:
  // Copyable and movable.
  CompositeMlDsaPrivateKey(const CompositeMlDsaPrivateKey& other);
  CompositeMlDsaPrivateKey& operator=(const CompositeMlDsaPrivateKey& other);
  CompositeMlDsaPrivateKey(CompositeMlDsaPrivateKey&& other) = default;
  CompositeMlDsaPrivateKey& operator=(CompositeMlDsaPrivateKey&& other) =
      default;

  static absl::StatusOr<CompositeMlDsaPrivateKey> Create(
      const CompositeMlDsaParameters& parameters,
      const MlDsaPrivateKey& ml_dsa_private_key,
      std::unique_ptr<SignaturePrivateKey> classical_private_key,
      absl::optional<int> id_requirement,
      PartialKeyAccessToken token);

  const CompositeMlDsaPublicKey& GetPublicKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND override {
    return public_key_;
  }
  const MlDsaPrivateKey& GetMlDsaPrivateKey() const
    ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return ml_dsa_private_key_;
  }
  const SignaturePrivateKey& GetClassicalPrivateKey() const
      ABSL_ATTRIBUTE_LIFETIME_BOUND {
    return *classical_private_key_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override;

 private:
  explicit CompositeMlDsaPrivateKey(
      const CompositeMlDsaPublicKey& public_key,
      const MlDsaPrivateKey& ml_dsa_private_key,
      std::unique_ptr<SignaturePrivateKey> classical_private_key)
      : public_key_(public_key),
        ml_dsa_private_key_(ml_dsa_private_key),
        classical_private_key_(std::move(classical_private_key)) {}

  CompositeMlDsaPublicKey public_key_;
  MlDsaPrivateKey ml_dsa_private_key_;
  std::unique_ptr<SignaturePrivateKey> classical_private_key_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_COMPOSITE_ML_DSA_PRIVATE_KEY_H_
