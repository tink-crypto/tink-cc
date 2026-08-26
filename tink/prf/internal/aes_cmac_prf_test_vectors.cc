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

#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"

#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

using ::crypto::tink::test::HexDecodeOrDie;

namespace {

struct AesCmacPrfTestVectorParams {
  absl::string_view key_hex;
  absl::string_view msg_hex;
  absl::string_view output_hex;
};

AesCmacPrfTestVector MakeAesCmacPrfTestVector(
    const AesCmacPrfTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  absl::StatusOr<AesCmacPrfKey> key = AesCmacPrfKey::Create(
      RestrictedData(HexDecodeOrDie(params.key_hex), ska), pka);
  ABSL_CHECK_OK(key);
  return AesCmacPrfTestVector{*std::move(key), HexDecodeOrDie(params.msg_hex),
                              HexDecodeOrDie(params.output_hex)};
}

using AesCmacPrfTestVectorMap = absl::flat_hash_map<int, AesCmacPrfTestVector>;

const AesCmacPrfTestVectorMap& CreateAesCmacPrfTestVectorsMap() {
  static const absl::NoDestructor<AesCmacPrfTestVectorMap> test_vectors(
      AesCmacPrfTestVectorMap{
          {16, MakeAesCmacPrfTestVector(AesCmacPrfTestVectorParams{
                   /*key_hex=*/"2b7e151628aed2a6abf7158809cf4f3c",
                   /*msg_hex=*/"",
                   /*output_hex=*/"bb1d6929e95937287fa37d129b756746",
               })},
          {32, MakeAesCmacPrfTestVector(AesCmacPrfTestVectorParams{
                   /*key_hex=*/
                   "00112233445566778899aabbccddeeff0011223344556677"
                   "8899aabbccddeeff",
                   /*msg_hex=*/
                   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                   "bbbbbbbbbbbbbbbbbb",
                   /*output_hex=*/"139fce15a6f4a281ad22458d3d3cac26",
               })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AesCmacPrfTestVector>& CreateAesCmacPrfTestVectors() {
  static const absl::NoDestructor<std::vector<AesCmacPrfTestVector>>
      test_vectors([] {
        std::vector<AesCmacPrfTestVector> result;
        result.reserve(CreateAesCmacPrfTestVectorsMap().size());
        for (const auto& [unused_params, test_vector] :
             CreateAesCmacPrfTestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const AesCmacPrfTestVector& GetAesCmacPrfTestVector(int key_size_in_bytes) {
  const AesCmacPrfTestVectorMap& test_vectors_map =
      CreateAesCmacPrfTestVectorsMap();
  auto it = test_vectors_map.find(key_size_in_bytes);
  ABSL_CHECK(it != test_vectors_map.end())
      << "AesCmacPrfTestVector not found for AES-CMAC PRF key with size "
      << key_size_in_bytes;
  return it->second;
}

}  // namespace crypto::tink::internal
