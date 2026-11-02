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
#include "absl/time/time.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto::tink::jwt_internal {

namespace {

// 64-byte HMAC key from RFC 7515, Appendix A.1 ("Example JWS Using HMAC
// SHA-256"): https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1.
// Also used in third_party/tink/cc/jwt/internal/jwt_mac_config_2026_test.cc
// and third_party/tink/go/jwt/jwt_full_mac_test.go (TestJWTFullMACTestVectors).
constexpr absl::string_view kRfc7515KeyBase64 =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-"
    "1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

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
  std::string signed_jwt;
  std::string expected_issuer;
  std::optional<absl::Time> fixed_now = std::nullopt;
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
  JwtValidatorBuilder validator_builder =
      JwtValidatorBuilder().ExpectIssuer(params.expected_issuer);
  if (params.fixed_now.has_value()) {
    validator_builder.SetFixedNow(*params.fixed_now);
  } else {
    validator_builder.AllowMissingExpiration();
  }
  absl::StatusOr<JwtValidator> validator = validator_builder.Build();
  ABSL_CHECK_OK(validator.status());
  return JwtHmacTestVector{*std::move(key), params.signed_jwt,
                           *std::move(validator)};
}

using JwtHmacTestVectorMap =
    absl::flat_hash_map<JwtHmacParameters::Algorithm, JwtHmacTestVector>;

const JwtHmacTestVectorMap& CreateJwtHmacTestVectorsMap() {
  static const absl::NoDestructor<JwtHmacTestVectorMap> test_vectors([] {
    std::string key_bytes = DecodeOrDie(kRfc7515KeyBase64);
    int key_size_in_bytes = key_bytes.size();
    return JwtHmacTestVectorMap{
        // Test vector from:
        // - third_party/tink/cc/jwt/internal/jwt_mac_config_2026_test.cc
        //   (GetJwtMacTestParams, HS256 with KidStrategy::kBase64EncodedKeyId)
        // - third_party/tink/go/jwt/jwt_full_mac_test.go
        //   (TestJWTFullMACTestVectors, "HS256_Base64EncodedKeyIDAsKID")
        // Key: 64-byte key from RFC 7515, Appendix A.1.
        // ID requirement: 0x01020304 (base64url-encoded big-endian key ID
        // "AQIDBA").
        {JwtHmacParameters::Algorithm::kHs256,
         MakeJwtHmacTestVector(JwtHmacTestVectorParams{
             /*key_size_in_bytes=*/key_size_in_bytes,
             /*kid_strategy=*/
             JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
             /*algorithm=*/JwtHmacParameters::Algorithm::kHs256,
             /*key=*/key_bytes,
             /*signed_jwt=*/
             // Header: {"kid":"AQIDBA","alg":"HS256"}
             "eyJraWQiOiJBUUlEQkEiLCJhbGciOiJIUzI1NiJ9."
             // Payload: {"iss":"issuer"}
             "eyJpc3MiOiJpc3N1ZXIifQ."
             // HMAC-SHA256 tag:
             "LyeYhbBBMFNjdGo_Qz3SXB7QvYbb-i0Onswr5R7zKvg",
             /*expected_issuer=*/"issuer",
             /*fixed_now=*/std::nullopt,
             /*id_requirement=*/0x01020304,
             /*custom_kid=*/std::nullopt,
         })},
        // Test vector from:
        // - third_party/tink/go/jwt/jwt_full_mac_test.go
        //   (TestJWTFullMACTestVectors, "HS384_CustomKID")
        // Key: 64-byte key from RFC 7515, Appendix A.1.
        // Custom KID: "custom-kid".
        {JwtHmacParameters::Algorithm::kHs384,
         MakeJwtHmacTestVector(JwtHmacTestVectorParams{
             /*key_size_in_bytes=*/key_size_in_bytes,
             /*kid_strategy=*/JwtHmacParameters::KidStrategy::kCustom,
             /*algorithm=*/JwtHmacParameters::Algorithm::kHs384,
             /*key=*/key_bytes,
             /*signed_jwt=*/
             // Header: {"kid":"custom-kid","alg":"HS384"}
             "eyJraWQiOiJjdXN0b20ta2lkIiwiYWxnIjoiSFMzODQifQ."
             // Payload: {"iss":"issuer"}
             "eyJpc3MiOiJpc3N1ZXIifQ."
             // HMAC-SHA384 tag:
             "cd6Lfc4GKiM60UNT4uJtEKaus2BFOeSAS5sAsuddnFnM2xymi4R2ovKU9UVDdwNM",
             /*expected_issuer=*/"issuer",
             /*fixed_now=*/std::nullopt,
             /*id_requirement=*/std::nullopt,
             /*custom_kid=*/"custom-kid",
         })},
        // Test vector from:
        // - third_party/tink/go/jwt/jwt_full_mac_test.go
        //   (TestJWTFullMACTestVectors, "HS512_IgnoredKID")
        // Key: 64-byte key from RFC 7515, Appendix A.1.
        // Payload from RFC 7515, Appendix A.1.
        {JwtHmacParameters::Algorithm::kHs512,
         MakeJwtHmacTestVector(JwtHmacTestVectorParams{
             /*key_size_in_bytes=*/key_size_in_bytes,
             /*kid_strategy=*/JwtHmacParameters::KidStrategy::kIgnored,
             /*algorithm=*/JwtHmacParameters::Algorithm::kHs512,
             /*key=*/key_bytes,
             /*signed_jwt=*/
             // Header: {"alg":"HS512"}
             "eyJhbGciOiJIUzUxMiJ9."
             // Payload:
             // {"iss":"joe",
             //  "exp":1300819380,
             //  "http://example.com/is_root":true}
             "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
             "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
             // HMAC-SHA512 tag:
             "CyfHecbVPqPzB3zBwYd3rgVBi2Dgg-eAeX7JT8B85QbKLwSXyll8WKGdehse606s"
             "zf9G3i-jr24QGkEtMAGSpg",
             /*expected_issuer=*/"joe",
             /*fixed_now=*/absl::FromUnixSeconds(1300819380 - 3600),
             /*id_requirement=*/std::nullopt,
             /*custom_kid=*/std::nullopt,
         })},
    };
  }());
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

const JwtHmacTestVector& GetJwtHmacTestVector(
    JwtHmacParameters::Algorithm algorithm) {
  const JwtHmacTestVectorMap& map = CreateJwtHmacTestVectorsMap();
  auto it = map.find(algorithm);
  ABSL_CHECK(it != map.end()) << "No JWT HMAC test vector found for algorithm: "
                              << static_cast<int>(algorithm);
  return it->second;
}

}  // namespace crypto::tink::jwt_internal
