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

#include "tink/daead/internal/aes_siv_test_vectors.h"

#include <optional>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
struct AesSivTestVectorParams {
  int key_size_in_bytes ABSL_REQUIRE_EXPLICIT_INIT;
  AesSivParameters::Variant variant;
  absl::string_view key_hex;
  absl::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view aad_hex;
  absl::string_view ciphertext_hex;
};

AesSivTestVector MakeAesSivTestVector(const AesSivTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  absl::StatusOr<AesSivParameters> parameters =
      AesSivParameters::Create(params.key_size_in_bytes, params.variant);
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      *parameters, RestrictedData(HexDecodeOrDie(params.key_hex), ska),
      params.id_requirement, pka);
  ABSL_CHECK_OK(key);
  return AesSivTestVector{*key, HexDecodeOrDie(params.plaintext_hex),
                          HexDecodeOrDie(params.aad_hex),
                          HexDecodeOrDie(params.ciphertext_hex)};
}

using AesSivTestVectorMap =
    absl::flat_hash_map<std::pair<int, AesSivParameters::Variant>,
                        AesSivTestVector>;

const AesSivTestVectorMap& CreateAesSivTestVectorsMap() {
  static const absl::NoDestructor<AesSivTestVectorMap> test_vectors(
      AesSivTestVectorMap{
          {{32, AesSivParameters::Variant::kNoPrefix},
           MakeAesSivTestVector(AesSivTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesSivParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7"
               "f8f9fafbfcfdfeff",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/"112233445566778899aabbccddee",
               /*aad_hex=*/"101112131415161718191a1b1c1d1e1f2021222324252627",
               /*ciphertext_hex=*/
               "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6a"
               "fe5c",
           })},
          {{48, AesSivParameters::Variant::kNoPrefix},
           MakeAesSivTestVector(AesSivTestVectorParams{
               /*key_size_in_bytes=*/48,
               /*variant=*/AesSivParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "d3d58a2f21e62f5095542e618168ef040922ab7d80b38400"
               "55eb9caf5726a8d4a7f071dc40ddb320effc094211735090",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/"",
               /*aad_hex=*/"",
               /*ciphertext_hex=*/"59e0a9a04cdb1d9d7bee6be8bb06fd61",
           })},
          {{64, AesSivParameters::Variant::kNoPrefix},
           MakeAesSivTestVector(AesSivTestVectorParams{
               /*key_size_in_bytes=*/64,
               /*variant=*/AesSivParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980"
               "401a981030254a54b1756a8c96e600b7252fd0aab12f39d1"
               "15d256b3f3e7c2c41a7fece72ba7c3c4",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/"",
               /*aad_hex=*/"",
               /*ciphertext_hex=*/"44b1c6fe8a8c07dee5377b161f283c31",
           })},
          {{64, AesSivParameters::Variant::kTink},
           MakeAesSivTestVector(AesSivTestVectorParams{
               /*key_size_in_bytes=*/64,
               /*variant=*/AesSivParameters::Variant::kTink,
               /*key_hex=*/
               "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980"
               "401a981030254a54b1756a8c96e600b7252fd0aab12f39d1"
               "15d256b3f3e7c2c41a7fece72ba7c3c4",
               /*id_requirement=*/0x02030400,
               /*plaintext_hex=*/"",
               /*aad_hex=*/"",
               /*ciphertext_hex=*/"010203040044b1c6fe8a8c07dee5377b161f283c31",
           })},
          {{64, AesSivParameters::Variant::kCrunchy},
           MakeAesSivTestVector(AesSivTestVectorParams{
               /*key_size_in_bytes=*/64,
               /*variant=*/AesSivParameters::Variant::kCrunchy,
               /*key_hex=*/
               "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980"
               "401a981030254a54b1756a8c96e600b7252fd0aab12f39d1"
               "15d256b3f3e7c2c41a7fece72ba7c3c4",
               /*id_requirement=*/0x01030005,
               /*plaintext_hex=*/"",
               /*aad_hex=*/"",
               /*ciphertext_hex=*/"000103000544b1c6fe8a8c07dee5377b161f283c31",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AesSivTestVector>& CreateAesSivTestVectors() {
  static const absl::NoDestructor<std::vector<AesSivTestVector>> test_vectors(
      [] {
        std::vector<AesSivTestVector> result;
        result.reserve(CreateAesSivTestVectorsMap().size());
        for (const auto& [unused_params, test_vector] :
             CreateAesSivTestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const AesSivTestVector& GetAesSivTestVector(int key_size_in_bytes,
                                            AesSivParameters::Variant variant) {
  const AesSivTestVectorMap& test_vectors_map = CreateAesSivTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AesSivTestVector not found for AES-SIV key with size "
      << key_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
