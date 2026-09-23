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

#include "tink/jwt/internal/jwt_ml_dsa_signer.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/raw_jwt_ml_dsa_signer.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/public_key_sign.h"
namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

// Algorithm names taken from
// https://www.rfc-editor.org/rfc/rfc9964.html#name-ml-dsa-algorithms
absl::StatusOr<std::string> AlgorithmName(
    const JwtMlDsaParameters::Algorithm& algorithm) {
  switch (algorithm) {
    case JwtMlDsaParameters::Algorithm::kMlDsa44:
      return std::string("ML-DSA-44");
    case JwtMlDsaParameters::Algorithm::kMlDsa65:
      return std::string("ML-DSA-65");
    case JwtMlDsaParameters::Algorithm::kMlDsa87:
      return std::string("ML-DSA-87");
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
NewJwtMlDsaSignInternal(const JwtMlDsaPrivateKey& jwt_ml_dsa_private_key) {
  absl::StatusOr<std::unique_ptr<PublicKeySign>> raw_signer =
      NewRawJwtMlDsaSign(jwt_ml_dsa_private_key);
  if (!raw_signer.ok()) {
    return raw_signer.status();
  }

  JwtMlDsaParameters jwt_ml_dsa_params = jwt_ml_dsa_private_key.GetParameters();

  absl::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_ml_dsa_params.GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_ml_dsa_params.GetKidStrategy()) {
    case JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId: {
      std::string kid = jwt_ml_dsa_private_key.GetPublicKey().GetKid().value();
      return JwtPublicKeySignImpl::WithKid(*std::move(raw_signer),
                                           *algorithm_name, kid);
    }
    case JwtMlDsaParameters::KidStrategy::kCustom: {
      std::string custom_kid =
          jwt_ml_dsa_private_key.GetPublicKey().GetKid().value();
      return JwtPublicKeySignImpl::RawWithCustomKid(
          *std::move(raw_signer), *algorithm_name, custom_kid);
    }
    case JwtMlDsaParameters::KidStrategy::kIgnored:
      return JwtPublicKeySignImpl::Raw(*std::move(raw_signer), *algorithm_name);
    default:
      // Should never happen.
      return absl::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
