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

#include "tink/jwt/internal/jwt_hmac.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/mac.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hmac_boringssl.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

struct HashAndTagSize {
  subtle::HashType hash_type;
  int tag_size;
};

absl::StatusOr<HashAndTagSize> HashTypeAndTagSize(
    JwtHmacParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtHmacParameters::Algorithm::kHs256:
      return HashAndTagSize{subtle::HashType::SHA256, 32};
    case JwtHmacParameters::Algorithm::kHs384:
      return HashAndTagSize{subtle::HashType::SHA384, 48};
    case JwtHmacParameters::Algorithm::kHs512:
      return HashAndTagSize{subtle::HashType::SHA512, 64};
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported algorithm");
  }
}

absl::StatusOr<std::string> AlgorithmName(
    JwtHmacParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtHmacParameters::Algorithm::kHs256:
      return "HS256";
    case JwtHmacParameters::Algorithm::kHs384:
      return "HS384";
    case JwtHmacParameters::Algorithm::kHs512:
      return "HS512";
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported algorithm");
  }
}

class JwtHmacImpl : public JwtMac {
 public:
  explicit JwtHmacImpl(std::unique_ptr<JwtMacImpl> impl,
                       std::optional<std::string> kid)
      : impl_(std::move(impl)), kid_(std::move(kid)) {}

  absl::StatusOr<std::string> ComputeMacAndEncode(
      const RawJwt& token) const override {
    return impl_->ComputeMacAndEncodeWithKid(token, kid_);
  }

  absl::StatusOr<VerifiedJwt> VerifyMacAndDecode(
      absl::string_view compact, const JwtValidator& validator) const override {
    return impl_->VerifyMacAndDecodeWithKid(compact, validator, kid_);
  }

 private:
  std::unique_ptr<JwtMacImpl> impl_;
  std::optional<std::string> kid_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<JwtMac>> NewJwtHmac(const JwtHmacKey& key) {
  const JwtHmacParameters& jwt_hmac_params = key.GetParameters();
  absl::StatusOr<HashAndTagSize> hash_and_tag_size =
      HashTypeAndTagSize(jwt_hmac_params.GetAlgorithm());
  if (!hash_and_tag_size.ok()) {
    return hash_and_tag_size.status();
  }

  absl::StatusOr<std::unique_ptr<Mac>> raw_mac = subtle::HmacBoringSsl::New(
      hash_and_tag_size->hash_type, hash_and_tag_size->tag_size,
      key.GetKeyBytes(GetPartialKeyAccess())
          .Get(internal::GetInsecureSecretKeyAccessInternal()));
  if (!raw_mac.ok()) {
    return raw_mac.status();
  }

  absl::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_hmac_params.GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_hmac_params.GetKidStrategy()) {
    case JwtHmacParameters::KidStrategy::kIgnored:
      return std::make_unique<JwtHmacImpl>(
          JwtMacImpl::Raw(*std::move(raw_mac), *algorithm_name), std::nullopt);
    case JwtHmacParameters::KidStrategy::kCustom:
      return std::make_unique<JwtHmacImpl>(
          JwtMacImpl::RawWithCustomKid(*std::move(raw_mac), *algorithm_name,
                                       *key.GetKid()),
          std::nullopt);
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId:
      return std::make_unique<JwtHmacImpl>(
          JwtMacImpl::WithKid(*std::move(raw_mac), *algorithm_name,
                              *key.GetKid()),
          key.GetKid());
    default:
      return absl::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
