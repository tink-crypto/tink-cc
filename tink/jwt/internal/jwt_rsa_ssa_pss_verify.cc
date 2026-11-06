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

#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/internal/jwt_public_key_verify_impl.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

absl::StatusOr<std::string> AlgorithmName(
    JwtRsaSsaPssParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssParameters::Algorithm::kPs256:
      return std::string("PS256");
    case JwtRsaSsaPssParameters::Algorithm::kPs384:
      return std::string("PS384");
    case JwtRsaSsaPssParameters::Algorithm::kPs512:
      return std::string("PS512");
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

class JwtRsaSsaPssVerifyImpl : public JwtPublicKeyVerify {
 public:
  explicit JwtRsaSsaPssVerifyImpl(std::unique_ptr<JwtPublicKeyVerifyImpl> impl)
      : impl_(std::move(impl)) {}

  absl::StatusOr<VerifiedJwt> VerifyAndDecode(
      absl::string_view compact, const JwtValidator& validator) const override {
    return impl_->VerifyAndDecode(compact, validator);
  }

 private:
  std::unique_ptr<JwtPublicKeyVerifyImpl> impl_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>> NewJwtRsaSsaPssVerify(
    const JwtRsaSsaPssPublicKey& key) {
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> raw_verifier =
      subtle::RsaSsaPssVerifyBoringSsl::New(
          key.GetRsaSsaPssPublicKey(GetPartialKeyAccess()));
  if (!raw_verifier.ok()) {
    return raw_verifier.status();
  }

  const JwtRsaSsaPssParameters& params = key.GetParameters();
  absl::StatusOr<std::string> algorithm_name =
      AlgorithmName(params.GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (params.GetKidStrategy()) {
    case JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId:
      return std::make_unique<JwtRsaSsaPssVerifyImpl>(
          JwtPublicKeyVerifyImpl::WithKid(*std::move(raw_verifier),
                                          *algorithm_name, *key.GetKid()));
    case JwtRsaSsaPssParameters::KidStrategy::kCustom:
      return std::make_unique<JwtRsaSsaPssVerifyImpl>(
          JwtPublicKeyVerifyImpl::RawWithCustomKid(
              *std::move(raw_verifier), *algorithm_name, *key.GetKid()));
    case JwtRsaSsaPssParameters::KidStrategy::kIgnored:
      return std::make_unique<JwtRsaSsaPssVerifyImpl>(
          JwtPublicKeyVerifyImpl::Raw(*std::move(raw_verifier),
                                      *algorithm_name));
    default:
      return absl::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
