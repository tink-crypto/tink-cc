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

#include "tink/jwt/jwt_ml_dsa_private_key.h"

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<MlDsaParameters> ToMlDsaParametersWithNoPrefix(
    const JwtMlDsaParameters& parameters) {
  switch (parameters.GetAlgorithm()) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44:
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa44,
                                     MlDsaParameters::Variant::kNoPrefix);
    case JwtMlDsaParameters::Algorithm::kMlDsa65:
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                     MlDsaParameters::Variant::kNoPrefix);
    case JwtMlDsaParameters::Algorithm::kMlDsa87:
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                     MlDsaParameters::Variant::kNoPrefix);
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown JWT ML-DSA algorithm");
  }
}

absl::StatusOr<MlDsaPublicKey> ToMlDsaPublicKeyWithNoPrefix(
    const JwtMlDsaPublicKey& public_key) {
  absl::StatusOr<MlDsaParameters> ml_dsa_parameters =
      ToMlDsaParametersWithNoPrefix(public_key.GetParameters());
  if (!ml_dsa_parameters.ok()) {
    return ml_dsa_parameters.status();
  }
  return MlDsaPublicKey::Create(
      *ml_dsa_parameters, public_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
}

// Returns true if the corresponding ML-DSA key pair is valid.
absl::Status ValidateKeyPair(const JwtMlDsaPublicKey& jwt_ml_dsa_public_key,
                             const RestrictedData& private_seed_bytes) {
  absl::StatusOr<MlDsaPublicKey> ml_dsa_public_key =
      ToMlDsaPublicKeyWithNoPrefix(jwt_ml_dsa_public_key);
  if (!ml_dsa_public_key.ok()) {
    return ml_dsa_public_key.status();
  }
  absl::StatusOr<MlDsaPrivateKey> ml_dsa_private_key = MlDsaPrivateKey::Create(
      *ml_dsa_public_key, private_seed_bytes, GetPartialKeyAccess());
  if (!ml_dsa_private_key.ok()) {
    return ml_dsa_private_key.status();
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<JwtMlDsaPrivateKey> JwtMlDsaPrivateKey::Create(
    const JwtMlDsaPublicKey& public_key,
    const RestrictedData& private_seed_bytes, PartialKeyAccessToken token) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "ML-DSA is only supported in BoringSSL builds.");
#else
  if (private_seed_bytes.size() != MLDSA_SEED_BYTES) {
    return absl::InvalidArgumentError(
        absl::StrCat("Private key length ", private_seed_bytes.size(),
                     " is different from expected length ", MLDSA_SEED_BYTES));
  }

  absl::Status valid_key_pair_status =
      ValidateKeyPair(public_key, private_seed_bytes);
  if (!valid_key_pair_status.ok()) {
    return valid_key_pair_status;
  }

  return JwtMlDsaPrivateKey(public_key, private_seed_bytes);
#endif
}

bool JwtMlDsaPrivateKey::operator==(const Key& other) const {
  const JwtMlDsaPrivateKey* that =
      dynamic_cast<const JwtMlDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (public_key_ != that->public_key_) {
    return false;
  }
  if (private_seed_bytes_ != that->private_seed_bytes_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
