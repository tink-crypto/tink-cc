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

#include "tink/prf/internal/hmac_prf_test_vectors.h"

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
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

using ::crypto::tink::test::HexDecodeOrDie;

namespace {

struct HmacPrfTestVectorParams {
  int key_size_in_bytes;
  HmacPrfParameters::HashType hash_type;
  absl::string_view key_hex;
  absl::string_view msg_hex;
  absl::string_view output_hex;
};

HmacPrfTestVector MakeHmacPrfTestVector(const HmacPrfTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();

  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(params.key_size_in_bytes, params.hash_type);
  ABSL_CHECK_OK(parameters);

  absl::StatusOr<HmacPrfKey> key = HmacPrfKey::Create(
      *std::move(parameters),
      RestrictedData(HexDecodeOrDie(params.key_hex), ska), pka);
  ABSL_CHECK_OK(key);

  return HmacPrfTestVector{*std::move(key), HexDecodeOrDie(params.msg_hex),
                           HexDecodeOrDie(params.output_hex)};
}

using HmacPrfTestVectorMap =
    absl::flat_hash_map<std::pair<int, HmacPrfParameters::HashType>,
                        HmacPrfTestVector>;

const HmacPrfTestVectorMap& CreateHmacPrfTestVectorsMap() {
  static const absl::NoDestructor<HmacPrfTestVectorMap> test_vectors(
      HmacPrfTestVectorMap{
          {{32, HmacPrfParameters::HashType::kSha1},
           MakeHmacPrfTestVector(HmacPrfTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*hash_type=*/HmacPrfParameters::HashType::kSha1,
               /*key_hex=*/
               "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c98"
               "8b46272",
               /*msg_hex=*/
               "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855"
               "d78301d837a0a2eb9e4f056f06c08361bd07180ee802651e69726c289"
               "10d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2"
               "b3d05260885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6"
               "a8cc72fbe0e52c01766fede78a1a",
               /*output_hex=*/"17cb2e9e98b748b5ae0f7078ea5519e5",
           })},
          {{40, HmacPrfParameters::HashType::kSha256},
           MakeHmacPrfTestVector(HmacPrfTestVectorParams{
               /*key_size_in_bytes=*/40,
               /*hash_type=*/HmacPrfParameters::HashType::kSha256,
               /*key_hex=*/
               "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806c"
               "b5df95febbdd61236f33245",
               /*msg_hex=*/
               "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d"
               "0970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f"
               "834039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284"
               "c3720570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b"
               "046a2759f82a54c41ccd7b5f592b",
               /*output_hex=*/"05d1243e6465ed9620c9aec1c351a186",
           })},
          {{20, HmacPrfParameters::HashType::kSha384},
           MakeHmacPrfTestVector(HmacPrfTestVectorParams{
               /*key_size_in_bytes=*/20,
               /*hash_type=*/HmacPrfParameters::HashType::kSha384,
               /*key_hex=*/"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               /*msg_hex=*/"4869205468657265",
               /*output_hex=*/
               "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec68"
               "2aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
           })},
          {{100, HmacPrfParameters::HashType::kSha512},
           MakeHmacPrfTestVector(HmacPrfTestVectorParams{
               /*key_size_in_bytes=*/100,
               /*hash_type=*/HmacPrfParameters::HashType::kSha512,
               /*key_hex=*/
               "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93"
               "abd0fba46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c"
               "10afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303e"
               "e0c910e64e87fbf302214edbe3f2",
               /*msg_hex=*/
               "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625"
               "f7aa59b89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75"
               "ae650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840e"
               "e83d3e7101c52cf652d2773531b7a6bdd690b846a741816c860819270"
               "522a5b0cdfa1d736c501c583d916",
               /*output_hex=*/
               "bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb17"
               "91f6569",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<HmacPrfTestVector>& CreateHmacPrfTestVectors() {
  static const absl::NoDestructor<std::vector<HmacPrfTestVector>> test_vectors(
      [] {
        std::vector<HmacPrfTestVector> result;
        result.reserve(CreateHmacPrfTestVectorsMap().size());
        for (const auto& [params, test_vector] :
             CreateHmacPrfTestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const HmacPrfTestVector& GetHmacPrfTestVector(
    int key_size_in_bytes, HmacPrfParameters::HashType hash_type) {
  const auto& test_vectors_map = CreateHmacPrfTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, hash_type));
  ABSL_CHECK(it != test_vectors_map.end())
      << "HmacPrfTestVector not found for HMAC PRF key with size "
      << key_size_in_bytes << " and hash_type " << static_cast<int>(hash_type);
  return it->second;
}

}  // namespace crypto::tink::internal
