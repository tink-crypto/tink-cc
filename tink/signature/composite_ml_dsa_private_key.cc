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

#include "tink/signature/composite_ml_dsa_private_key.h"

#include <memory>
#include <utility>

#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_public_key.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/signature/signature_public_key.h"

namespace crypto {
namespace tink {

CompositeMlDsaPrivateKey::CompositeMlDsaPrivateKey(
    const CompositeMlDsaPrivateKey& other)
    : public_key_(other.public_key_),
      ml_dsa_private_key_(other.ml_dsa_private_key_) {
  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *other.classical_private_key_);
  classical_private_key_ = std::move(classical_private_key_clone);
}

CompositeMlDsaPrivateKey& CompositeMlDsaPrivateKey::operator=(
    const CompositeMlDsaPrivateKey& other) {
  if (this == &other) {
    return *this;
  }
  public_key_ = other.public_key_;
  ml_dsa_private_key_ = other.ml_dsa_private_key_;
  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *other.classical_private_key_);
  classical_private_key_ = std::move(classical_private_key_clone);
  return *this;
}

absl::StatusOr<CompositeMlDsaPrivateKey> CompositeMlDsaPrivateKey::Create(
    const CompositeMlDsaParameters& parameters,
    const MlDsaPrivateKey& ml_dsa_private_key,
    std::unique_ptr<SignaturePrivateKey> classical_private_key,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  std::unique_ptr<SignaturePublicKey> classical_public_key =
      crypto::tink::internal::CloneKeyOrDie<SignaturePublicKey>(
          classical_private_key->GetPublicKey());
  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          parameters, ml_dsa_private_key.GetPublicKey(),
          std::move(classical_public_key), id_requirement, token);
  if (!public_key.ok()) {
    return public_key.status();
  }
  return CompositeMlDsaPrivateKey(*public_key, ml_dsa_private_key,
                                  std::move(classical_private_key));
}

bool CompositeMlDsaPrivateKey::operator==(const Key& other) const {
  const CompositeMlDsaPrivateKey* that =
      dynamic_cast<const CompositeMlDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         ml_dsa_private_key_ == that->ml_dsa_private_key_ &&
         *classical_private_key_ == *that->classical_private_key_;
}

std::unique_ptr<Key> CompositeMlDsaPrivateKey::Clone() const {
  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      crypto::tink::internal::CloneKeyOrDie<SignaturePrivateKey>(
          *classical_private_key_);
  return absl::WrapUnique(
      new CompositeMlDsaPrivateKey(public_key_, ml_dsa_private_key_,
                                   std::move(classical_private_key_clone)));
}

}  // namespace tink
}  // namespace crypto
