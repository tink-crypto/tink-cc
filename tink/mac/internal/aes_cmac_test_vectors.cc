// Copyright 2017 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/mac/internal/aes_cmac_test_vectors.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::HexDecodeOrDie;

namespace {

struct AesCmacTestVectorParams {
  absl::string_view test_name;
  absl::string_view key_hex;
  absl::string_view msg_hex;
  absl::string_view tag_hex;
};

TinkAesCmacTestVector MakeAesCmacTestVector(
    const AesCmacTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  std::string key_bytes = HexDecodeOrDie(params.key_hex);
  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      /*key_size_in_bytes=*/key_bytes.size(),
      /*cryptographic_tag_size_in_bytes=*/16,
      AesCmacParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*parameters, RestrictedData(key_bytes, ska),
                         /*id_requirement=*/std::nullopt, pka);
  ABSL_CHECK_OK(key.status());
  return TinkAesCmacTestVector{
      std::string(params.test_name),
      *std::move(key),
      HexDecodeOrDie(params.msg_hex),
      HexDecodeOrDie(params.tag_hex),
  };
}

using AesCmacTestVectorMap = absl::flat_hash_map<int, TinkAesCmacTestVector>;

const AesCmacTestVectorMap& CreateAesCmacTestVectorsMap() {
  static const absl::NoDestructor<AesCmacTestVectorMap> test_vectors(
      AesCmacTestVectorMap{
          // From Wycheproof aes_cmac_test.json (tcId: 1)
          {16, MakeAesCmacTestVector(AesCmacTestVectorParams{
                   /*test_name=*/"WYCHEPROOF_128_BIT_TEST_VECTOR",
                   /*key_hex=*/"e34f15c7bd819930fe9d66e0c166e61c",
                   /*msg_hex=*/"",
                   /*tag_hex=*/"d47afca1d857a5933405b1eb7a5cb7af",
               })},
          // From Wycheproof aes_cmac_test.json (tcId: 205)
          {32, MakeAesCmacTestVector(AesCmacTestVectorParams{
                   /*test_name=*/"WYCHEPROOF_256_BIT_TEST_VECTOR",
                   /*key_hex=*/
                   "7bf9e536b66a215c22233fe2daaa743a898b9acb9f7802de70b40e3d6e"
                   "43ef97",
                   /*msg_hex=*/"",
                   /*tag_hex=*/"736c7b56957db774c5ddf7c7a70ba8a8",
               })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<TinkAesCmacTestVector>& AesCmacTestVectors() {
  static const absl::NoDestructor<std::vector<TinkAesCmacTestVector>>
      test_vectors([] {
        const AesCmacTestVectorMap& test_vectors_map =
            CreateAesCmacTestVectorsMap();
        std::vector<TinkAesCmacTestVector> result;
        result.reserve(test_vectors_map.size());
        for (const auto& [unused_params, test_vector] : test_vectors_map) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const TinkAesCmacTestVector& GetAesCmacTestVector(int key_size_in_bytes) {
  const AesCmacTestVectorMap& test_vectors_map = CreateAesCmacTestVectorsMap();
  auto it = test_vectors_map.find(key_size_in_bytes);
  ABSL_CHECK(it != test_vectors_map.end())
      << "TinkAesCmacTestVector not found for AES-CMAC key with size "
      << key_size_in_bytes;
  return it->second;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
