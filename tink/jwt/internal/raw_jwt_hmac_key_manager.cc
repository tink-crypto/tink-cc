// Copyright 2017 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"


#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::JwtHmacAlgorithm;
using google::crypto::tink::JwtHmacKey;
using google::crypto::tink::JwtHmacKeyFormat;

namespace {

absl::StatusOr<int> MinimumKeySize(const JwtHmacAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtHmacAlgorithm::HS256:
      return 32;
    case JwtHmacAlgorithm::HS384:
      return 48;
    case JwtHmacAlgorithm::HS512:
      return 64;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported algorithm.");
  }
}

}  // namespace

absl::StatusOr<JwtHmacKey> RawJwtHmacKeyManager::CreateKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format) const {
  JwtHmacKey jwt_hmac_key;
  jwt_hmac_key.set_version(get_version());
  jwt_hmac_key.set_algorithm(jwt_hmac_key_format.algorithm());
  jwt_hmac_key.set_key_value(
      subtle::Random::GetRandomBytes(jwt_hmac_key_format.key_size()));
  return jwt_hmac_key;
}

absl::Status RawJwtHmacKeyManager::ValidateKey(const JwtHmacKey& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  absl::StatusOr<int> min_key_size = MinimumKeySize(key.algorithm());
  if (!min_key_size.ok()) {
    return min_key_size.status();
  }
  if (key.key_value().size() < *min_key_size) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid JwtHmacKey: key_value is too short.");
  }
  return absl::OkStatus();
}

// static
absl::Status RawJwtHmacKeyManager::ValidateKeyFormat(
    const JwtHmacKeyFormat& key_format) const {
  absl::StatusOr<int> min_key_size = MinimumKeySize(key_format.algorithm());
  if (!min_key_size.ok()) {
    return min_key_size.status();
  }
  if (key_format.key_size() < *min_key_size) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacKeyFormat: key_size is too small.");
  }
  return absl::OkStatus();
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
