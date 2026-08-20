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

#include "tink/jwt/internal/testing/jwt_hmac_test_vectors.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto::tink::jwt_internal {

namespace {

// Helper to decode web safe base64 strings into raw bytes.
std::string DecodeOrDie(absl::string_view base64_string) {
  std::string dest;
  ABSL_CHECK(absl::WebSafeBase64Unescape(base64_string, &dest));
  return dest;
}

struct JwtHmacTestVectorParams {
  int key_size_in_bytes ABSL_REQUIRE_EXPLICIT_INIT;
  JwtHmacParameters::KidStrategy kid_strategy ABSL_REQUIRE_EXPLICIT_INIT;
  JwtHmacParameters::Algorithm algorithm ABSL_REQUIRE_EXPLICIT_INIT;
  std::string key;
  std::optional<int> id_requirement = std::nullopt;
  std::optional<std::string> custom_kid = std::nullopt;
};

JwtHmacTestVector MakeJwtHmacTestVector(const JwtHmacTestVectorParams& params) {
  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      params.key_size_in_bytes, params.kid_strategy, params.algorithm);
  ABSL_CHECK_OK(parameters.status());
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(params.key, InsecureSecretKeyAccess::Get()));
  if (params.id_requirement.has_value()) {
    builder.SetIdRequirement(*params.id_requirement);
  }
  if (params.custom_kid.has_value()) {
    builder.SetCustomKid(*params.custom_kid);
  }
  absl::StatusOr<JwtHmacKey> key = builder.Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return JwtHmacTestVector{*std::move(key)};
}

using JwtHmacTestVectorMap = absl::flat_hash_map<int, JwtHmacTestVector>;

const JwtHmacTestVectorMap& CreateJwtHmacTestVectorsMap() {
  static const absl::NoDestructor<JwtHmacTestVectorMap> test_vectors(
      JwtHmacTestVectorMap{
          {32, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/32,
                   /*kid_strategy=*/
                   JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
                   /*algorithm=*/JwtHmacParameters::Algorithm::kHs256,
                   /*key=*/
                   DecodeOrDie("-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBinggE"),
                   /*id_requirement=*/123,
                   /*custom_kid=*/std::nullopt,
               })},
          {48, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/48,
                   /*kid_strategy=*/JwtHmacParameters::KidStrategy::kCustom,
                   /*algorithm=*/JwtHmacParameters::Algorithm::kHs384,
                   /*key=*/"012345678901234567890123456789012345678901234567",
                   /*id_requirement=*/std::nullopt,
                   /*custom_kid=*/"custom_kid",
               })},
          {64, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/64,
                   /*kid_strategy=*/JwtHmacParameters::KidStrategy::kIgnored,
                   /*algorithm=*/JwtHmacParameters::Algorithm::kHs512,
                   /*key=*/
                   "0123456789012345678901234567890123456789012345678901"
                   "234567890123",
                   /*id_requirement=*/std::nullopt,
                   /*custom_kid=*/std::nullopt,
               })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<JwtHmacTestVector>& CreateJwtHmacTestVectors() {
  static const absl::NoDestructor<std::vector<JwtHmacTestVector>> test_vectors(
      [] {
        const JwtHmacTestVectorMap& test_vectors_map =
            CreateJwtHmacTestVectorsMap();
        std::vector<JwtHmacTestVector> result;
        result.reserve(test_vectors_map.size());
        for (const auto& [unused_params, test_vector] : test_vectors_map) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const JwtHmacTestVector& GetJwtHmacTestVector(int key_size_in_bytes) {
  const JwtHmacTestVectorMap& map = CreateJwtHmacTestVectorsMap();
  auto it = map.find(key_size_in_bytes);
  ABSL_CHECK(it != map.end())
      << "No JWT HMAC test vector found for key size: " << key_size_in_bytes;
  return it->second;
}

}  // namespace crypto::tink::jwt_internal
