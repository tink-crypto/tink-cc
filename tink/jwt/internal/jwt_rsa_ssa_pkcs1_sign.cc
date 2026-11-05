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

#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

absl::StatusOr<std::string> AlgorithmName(
    JwtRsaSsaPkcs1Parameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs256:
      return std::string("RS256");
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs384:
      return std::string("RS384");
    case JwtRsaSsaPkcs1Parameters::Algorithm::kRs512:
      return std::string("RS512");
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
  }
}

class JwtRsaSsaPkcs1SignImpl : public JwtPublicKeySign {
 public:
  explicit JwtRsaSsaPkcs1SignImpl(std::unique_ptr<JwtPublicKeySignImpl> impl)
      : impl_(std::move(impl)) {}

  absl::StatusOr<std::string> SignAndEncode(
      const RawJwt& token) const override {
    return impl_->SignAndEncode(token);
  }

 private:
  std::unique_ptr<JwtPublicKeySignImpl> impl_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> NewJwtRsaSsaPkcs1Sign(
    const JwtRsaSsaPkcs1PrivateKey& key) {
  absl::StatusOr<std::unique_ptr<PublicKeySign>> raw_signer =
      subtle::RsaSsaPkcs1SignBoringSsl::New(
          key.GetRsaSsaPkcs1PrivateKey(GetPartialKeyAccess()));
  if (!raw_signer.ok()) {
    return raw_signer.status();
  }

  const JwtRsaSsaPkcs1Parameters& params = key.GetPublicKey().GetParameters();
  absl::StatusOr<std::string> algorithm_name =
      AlgorithmName(params.GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (params.GetKidStrategy()) {
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId:
      return std::make_unique<JwtRsaSsaPkcs1SignImpl>(
          JwtPublicKeySignImpl::WithKid(*std::move(raw_signer), *algorithm_name,
                                        *key.GetPublicKey().GetKid()));
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom:
      return std::make_unique<JwtRsaSsaPkcs1SignImpl>(
          JwtPublicKeySignImpl::RawWithCustomKid(*std::move(raw_signer),
                                                 *algorithm_name,
                                                 *key.GetPublicKey().GetKid()));
    case JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored:
      return std::make_unique<JwtRsaSsaPkcs1SignImpl>(
          JwtPublicKeySignImpl::Raw(*std::move(raw_signer), *algorithm_name));
    default:
      return absl::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
