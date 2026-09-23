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

#include "tink/jwt/internal/raw_jwt_ml_dsa_verifier.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"


namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

absl::StatusOr<MlDsaParameters> RawMlDsaParametersFromJwtMlDsaParameters(
    const JwtMlDsaParameters& parameters) {
  switch (parameters.GetAlgorithm()) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44: {
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa44,
                                     MlDsaParameters::Variant::kNoPrefix);
    }
    case JwtMlDsaParameters::Algorithm::kMlDsa65: {
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                     MlDsaParameters::Variant::kNoPrefix);
    }
    case JwtMlDsaParameters::Algorithm::kMlDsa87: {
      return MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                     MlDsaParameters::Variant::kNoPrefix);
    }
    default:
      return absl::Status(absl::StatusCode::kInternal,
                          "Unknown JWT ML-DSA instance");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewRawJwtMlDsaVerify(
    const JwtMlDsaPublicKey& jwt_ml_dsa_public_key) {
  JwtMlDsaParameters jwt_ml_dsa_params = jwt_ml_dsa_public_key.GetParameters();
  absl::StatusOr<MlDsaParameters> raw_ml_dsa_parameters =
      RawMlDsaParametersFromJwtMlDsaParameters(jwt_ml_dsa_params);
  if (!raw_ml_dsa_parameters.ok()) {
    return raw_ml_dsa_parameters.status();
  }
  absl::StatusOr<MlDsaPublicKey> ml_dsa_public_key = MlDsaPublicKey::Create(
      *raw_ml_dsa_parameters,
      jwt_ml_dsa_public_key.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  if (!ml_dsa_public_key.ok()) {
    return ml_dsa_public_key.status();
  }
  return internal::NewMlDsaVerifyBoringSsl(*ml_dsa_public_key);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
