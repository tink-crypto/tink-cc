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

#include <string>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

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
  std::string key;
};

JwtHmacTestVector MakeJwtHmacTestVector(const JwtHmacTestVectorParams& params) {
  return JwtHmacTestVector{params.key};
}

using JwtHmacTestVectorMap = absl::flat_hash_map<int, JwtHmacTestVector>;

const JwtHmacTestVectorMap& CreateJwtHmacTestVectorsMap() {
  static const absl::NoDestructor<JwtHmacTestVectorMap> test_vectors(
      JwtHmacTestVectorMap{
          {32, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/32,
                   /*key=*/
                   DecodeOrDie("-ebuDNsVZ2iJtoZ-akfXTSCt4UO2cruLCsbWlBinggE"),
               })},
          {48, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/48,
                   /*key=*/"012345678901234567890123456789012345678901234567",
               })},
          {64, MakeJwtHmacTestVector(JwtHmacTestVectorParams{
                   /*key_size_in_bytes=*/64,
                   /*key=*/
                   "0123456789012345678901234567890123456789012345678901"
                   "234567890123",
               })},
      });
  return *test_vectors;
}

}  // namespace

const JwtHmacTestVector& GetJwtHmacTestVector(int key_size_in_bytes) {
  const JwtHmacTestVectorMap& map = CreateJwtHmacTestVectorsMap();
  auto it = map.find(key_size_in_bytes);
  ABSL_CHECK(it != map.end())
      << "No JWT HMAC test vector found for key size: " << key_size_in_bytes;
  return it->second;
}

}  // namespace crypto::tink::jwt_internal
