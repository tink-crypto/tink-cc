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

#include "tink/mac/internal/hmac_test_vectors.h"

#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

using ::crypto::tink::test::HexDecodeOrDie;

namespace {

struct HmacTestVectorParams {
  int tag_size;
  HmacParameters::HashType hash_type;
  HmacParameters::Variant variant;
  absl::string_view key_hex;
  absl::optional<int> id_requirement;
  absl::string_view msg_hex;
  absl::string_view tag_hex;
};

// Helper to construct an HmacTestVector from hex test values.
HmacTestVector MakeHmacTestVector(const HmacTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  std::string key_bytes = HexDecodeOrDie(params.key_hex);
  absl::StatusOr<HmacParameters> hmac_params = HmacParameters::Create(
      key_bytes.size(), params.tag_size, params.hash_type, params.variant);
  ABSL_CHECK_OK(hmac_params.status());
  absl::StatusOr<HmacKey> key = HmacKey::Create(
      *hmac_params, RestrictedData(key_bytes, ska), params.id_requirement, pka);
  ABSL_CHECK_OK(key.status());
  return HmacTestVector{*key, HexDecodeOrDie(params.msg_hex),
                        HexDecodeOrDie(params.tag_hex)};
}

using HmacTestVectorMap = absl::flat_hash_map<
    std::tuple<int, HmacParameters::HashType, HmacParameters::Variant>,
    HmacTestVector>;

const HmacTestVectorMap& CreateHmacTestVectorsMap() {
  static const absl::NoDestructor<HmacTestVectorMap> test_vectors(
      HmacTestVectorMap{
          {{32, HmacParameters::HashType::kSha1,
            HmacParameters::Variant::kNoPrefix},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/16,
               /*hash_type=*/HmacParameters::HashType::kSha1,
               /*variant=*/HmacParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988"
               "b46272",
               /*id_requirement=*/std::nullopt,
               /*msg_hex=*/
               "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d"
               "78301d837a0a2eb9e4f056f06c08361bd07180ee802651e69726c28910"
               "d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d"
               "05260885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc"
               "72fbe0e52c01766fede78a1a",
               /*tag_hex=*/"17cb2e9e98b748b5ae0f7078ea5519e5",
           })},
          {{40, HmacParameters::HashType::kSha256,
            HmacParameters::Variant::kNoPrefix},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/16,
               /*hash_type=*/HmacParameters::HashType::kSha256,
               /*variant=*/HmacParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb"
               "5df95febbdd61236f33245",
               /*id_requirement=*/std::nullopt,
               /*msg_hex=*/
               "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0"
               "970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f83"
               "4039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c37"
               "20570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a"
               "2759f82a54c41ccd7b5f592b",
               /*tag_hex=*/"05d1243e6465ed9620c9aec1c351a186",
           })},
          {{20, HmacParameters::HashType::kSha384,
            HmacParameters::Variant::kNoPrefix},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/48,
               /*hash_type=*/HmacParameters::HashType::kSha384,
               /*variant=*/HmacParameters::Variant::kNoPrefix,
               /*key_hex=*/"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               /*id_requirement=*/std::nullopt,
               /*msg_hex=*/"4869205468657265",
               /*tag_hex=*/"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec68"
                          "2aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
           })},
          {{100, HmacParameters::HashType::kSha512,
            HmacParameters::Variant::kNoPrefix},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/32,
               /*hash_type=*/HmacParameters::HashType::kSha512,
               /*variant=*/HmacParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93a"
               "bd0fba46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c10"
               "afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0"
               "c910e64e87fbf302214edbe3f2",
               /*id_requirement=*/std::nullopt,
               /*msg_hex=*/
               "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f"
               "7aa59b89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75ae"
               "650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83"
               "d3e7101c52cf652d2773531b7a6bdd690b846a741816c860819270522a"
               "5b0cdfa1d736c501c583d916",
               /*tag_hex=*/
               "bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f0133bad0fb179"
               "1f6569",
           })},
          {{32, HmacParameters::HashType::kSha1,
            HmacParameters::Variant::kLegacy},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/16,
               /*hash_type=*/HmacParameters::HashType::kSha1,
               /*variant=*/HmacParameters::Variant::kLegacy,
               /*key_hex=*/
               "816aa4c3ee066310ac1e6666cf830c375355c3c8ba18cfe1f50a48c988"
               "b46272",
               /*id_requirement=*/1234,
               /*msg_hex=*/
               "220248f5e6d7a49335b3f91374f18bb8b0ff5e8b9a5853f3cfb293855d"
               "78301d837a0a2eb9e4f056f06c08361bd07180ee802651e69726c28910"
               "d2baef379606815dcbab01d0dc7acb0ba8e65a2928130da0522f2b2b3d"
               "05260885cf1c64f14ca3145313c685b0274bf6a1cb38e4f99895c6a8cc"
               "72fbe0e52c01766fede78a1a",
               /*tag_hex=*/"00000004d20c2676610ded1bce1967ec654526ca7b",
           })},
          {{40, HmacParameters::HashType::kSha256,
            HmacParameters::Variant::kTink},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/16,
               /*hash_type=*/HmacParameters::HashType::kSha256,
               /*variant=*/HmacParameters::Variant::kTink,
               /*key_hex=*/
               "6f35628d65813435534b5d67fbdb54cb33403d04e843103e6399f806cb"
               "5df95febbdd61236f33245",
               /*id_requirement=*/1234,
               /*msg_hex=*/
               "752cff52e4b90768558e5369e75d97c69643509a5e5904e0a386cbe4d0"
               "970ef73f918f675945a9aefe26daea27587e8dc909dd56fd0468805f83"
               "4039b345f855cfe19c44b55af241fff3ffcd8045cd5c288e6c4e284c37"
               "20570b58e4d47b8feeedc52fd1401f698a209fccfa3b4c0d9a797b046a"
               "2759f82a54c41ccd7b5f592b",
               /*tag_hex=*/"01000004d205d1243e6465ed9620c9aec1c351a186",
           })},
          {{20, HmacParameters::HashType::kSha384,
            HmacParameters::Variant::kCrunchy},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/48,
               /*hash_type=*/HmacParameters::HashType::kSha384,
               /*variant=*/HmacParameters::Variant::kCrunchy,
               /*key_hex=*/"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               /*id_requirement=*/1234,
               /*msg_hex=*/"4869205468657265",
               /*tag_hex=*/
               "00000004d2afd03944d84895626b0825f4ab46907f15f9dadbe4101ec68"
               "2aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
           })},
          {{100, HmacParameters::HashType::kSha512,
            HmacParameters::Variant::kTink},
           MakeHmacTestVector(HmacTestVectorParams{
               /*tag_size=*/32,
               /*hash_type=*/HmacParameters::HashType::kSha512,
               /*variant=*/HmacParameters::Variant::kTink,
               /*key_hex=*/
               "726374c4b8df517510db9159b730f93431e0cd468d4f3821eab0edb93a"
               "bd0fba46ab4f1ef35d54fec3d85fa89ef72ff3d35f22cf5ab69e205c10"
               "afcdf4aaf11338dbb12073474fddb556e60b8ee52f91163ba314303ee0"
               "c910e64e87fbf302214edbe3f2",
               /*id_requirement=*/1234,
               /*msg_hex=*/
               "ac939659dc5f668c9969c0530422e3417a462c8b665e8db25a883a625f"
               "7aa59b89c5ad0ece5712ca17442d1798c6dea25d82c5db260cb59c75ae"
               "650be56569c1bd2d612cc57e71315917f116bbfa65a0aeb8af7840ee83"
               "d3e7101c52cf652d2773531b7a6bdd690b846a741816c860819270522a"
               "5b0cdfa1d736c501c583d916",
               /*tag_hex=*/
               "01000004d2bd3d2df6f9d284b421a43e5f9cb94bc4ff88a88243f1f013"
               "3bad0fb1791f6569",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<HmacTestVector>& CreateHmacTestVectors() {
  static const absl::NoDestructor<std::vector<HmacTestVector>> test_vectors([] {
    std::vector<HmacTestVector> result;
    result.reserve(CreateHmacTestVectorsMap().size());
    for (const auto& [params, test_vector] : CreateHmacTestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const HmacTestVector& GetHmacTestVector(int key_size_in_bytes,
                                        HmacParameters::HashType hash_type,
                                        HmacParameters::Variant variant) {
  const auto& test_vectors_map = CreateHmacTestVectorsMap();
  auto it = test_vectors_map.find(
      std::tuple(key_size_in_bytes, hash_type, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "HmacTestVector not found for HMAC key with size " << key_size_in_bytes
      << ", hash_type " << static_cast<int>(hash_type) << " and variant "
      << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
