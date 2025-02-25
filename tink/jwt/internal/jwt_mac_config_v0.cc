// Copyright 2024 Google LLC
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

#include "tink/jwt/internal/jwt_mac_config_v0.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/jwt/internal/jwt_hmac_key_manager.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/internal/jwt_mac_wrapper.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_hmac_proto_serialization.h"
#include "tink/mac.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

struct HashAndTagSize {
  subtle::HashType hash_type;
  int tag_size;
};

util::StatusOr<HashAndTagSize> HashTypeAndTagSize(
    JwtHmacParameters::Algorithm algorithm) {
  switch (algorithm) {
    case JwtHmacParameters::Algorithm::kHs256:
      return {{subtle::HashType::SHA256, 32}};
    case JwtHmacParameters::Algorithm::kHs384:
      return {{subtle::HashType::SHA384, 48}};
    case JwtHmacParameters::Algorithm::kHs512:
      return {{subtle::HashType::SHA512, 64}};
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported algorithm");
  }
}
util::StatusOr<std::string> AlgorithmName(
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

util::StatusOr<std::unique_ptr<JwtMacInternal>> NewJwHmacInternal(
    const JwtHmacKey& key) {
  const JwtHmacParameters& jwt_hmac_params = key.GetParameters();
  util::StatusOr<HashAndTagSize> hash_and_tag_size =
      HashTypeAndTagSize(jwt_hmac_params.GetAlgorithm());
  if (!hash_and_tag_size.ok()) {
    return hash_and_tag_size.status();
  }

  // Get a raw MAC primitive.
  util::StatusOr<std::unique_ptr<Mac>> raw_mac = subtle::HmacBoringSsl::New(
      hash_and_tag_size->hash_type, hash_and_tag_size->tag_size,
      key.GetKeyBytes(GetPartialKeyAccess())
          .Get(internal::GetInsecureSecretKeyAccessInternal()));
  if (!raw_mac.ok()) {
    return raw_mac.status();
  }

  util::StatusOr<std::string> algorithm_name =
      AlgorithmName(jwt_hmac_params.GetAlgorithm());
  if (!algorithm_name.ok()) {
    return algorithm_name.status();
  }

  switch (jwt_hmac_params.GetKidStrategy()) {
    case JwtHmacParameters::KidStrategy::kIgnored:
      return JwtMacImpl::Raw(*std::move(raw_mac), *algorithm_name);
    case JwtHmacParameters::KidStrategy::kCustom: {
      return JwtMacImpl::RawWithCustomKid(*std::move(raw_mac), *algorithm_name,
                                          key.GetKid().value());
    }
    case JwtHmacParameters::KidStrategy::kBase64EncodedKeyId: {
      // NOTE: This currently cannot be tested using Tink public APIs: the
      // keyset wrapper always deals with "RAW" keys.
      // https://github.com/tink-crypto/tink-cc/blob/ed2008a7b9f09b726a9fff4d96bb9b18093e71c3/tink/internal/keyset_wrapper_impl.h#L83
      return JwtMacImpl::WithKid(*std::move(raw_mac), *algorithm_name,
                                 key.GetKid().value());
    }
    default:
      // Should never happen.
      return absl::Status(absl::StatusCode::kInternal,
                          "Unsupported kid strategy");
  }
}

}  // namespace

absl::Status AddJwtMacV0(Configuration& config) {
  absl::Status status = RegisterJwtHmacProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveGetter<JwtMacInternal,
                                                           JwtHmacKey>(
      NewJwHmacInternal, config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<JwtMacWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddKeyTypeManager(
      absl::make_unique<JwtHmacKeyManager>(), config);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
