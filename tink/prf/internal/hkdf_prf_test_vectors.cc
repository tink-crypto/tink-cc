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

#include "tink/prf/internal/hkdf_prf_test_vectors.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct HkdfPrfTestVectorParams {
  int key_size_in_bytes ABSL_REQUIRE_EXPLICIT_INIT;
  HkdfPrfParameters::HashType hash_type;
  absl::optional<absl::string_view> salt_hex;
  absl::string_view key_hex;
  absl::string_view msg_hex;
  absl::string_view output_hex;
};

HkdfPrfTestVector MakeHkdfPrfTestVector(const HkdfPrfTestVectorParams& params) {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  absl::optional<std::string> salt;
  if (params.salt_hex.has_value()) {
    salt = HexDecodeOrDie(*params.salt_hex);
  }
  absl::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      params.key_size_in_bytes, params.hash_type, salt);
  ABSL_CHECK_OK(parameters);

  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      *std::move(parameters),
      RestrictedData(HexDecodeOrDie(params.key_hex), ska), pka);
  ABSL_CHECK_OK(key);

  return HkdfPrfTestVector{*std::move(key), HexDecodeOrDie(params.msg_hex),
                           HexDecodeOrDie(params.output_hex)};
}

using HkdfPrfTestVectorMap =
    absl::flat_hash_map<std::pair<int, HkdfPrfParameters::HashType>,
                        HkdfPrfTestVector>;

const HkdfPrfTestVectorMap& CreateHkdfPrfTestVectorsMap() {
  static const absl::NoDestructor<HkdfPrfTestVectorMap> test_vectors(
      HkdfPrfTestVectorMap{
          {{22, HkdfPrfParameters::HashType::kSha256},
           MakeHkdfPrfTestVector(HkdfPrfTestVectorParams{
               /*key_size_in_bytes=*/22,
               /*hash_type=*/HkdfPrfParameters::HashType::kSha256,
               /*salt_hex=*/"000102030405060708090a0b0c",
               /*key_hex=*/"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               /*msg_hex=*/"f0f1f2f3f4f5f6f7f8f9",
               /*output_hex=*/
               "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56"
               "ecc4c5bf34007208d5b887185865",
           })},
          {{80, HkdfPrfParameters::HashType::kSha256},
           MakeHkdfPrfTestVector(HkdfPrfTestVectorParams{
               /*key_size_in_bytes=*/80,
               /*hash_type=*/HkdfPrfParameters::HashType::kSha256,
               /*salt_hex=*/
               "606162636465666768696a6b6c6d6e6f7071727374757677"
               "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
               "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
               "a8a9aaabacadaeaf",
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f1011121314151617"
               "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
               "303132333435363738393a3b3c3d3e3f4041424344454647"
               "48494a4b4c4d4e4f",
               /*msg_hex=*/
               "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb"
               "cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7"
               "e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
               /*output_hex=*/
               "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c"
               "19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8"
               "367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
           })},
          {{80, HkdfPrfParameters::HashType::kSha1},
           MakeHkdfPrfTestVector(HkdfPrfTestVectorParams{
               /*key_size_in_bytes=*/80,
               /*hash_type=*/HkdfPrfParameters::HashType::kSha1,
               /*salt_hex=*/
               "606162636465666768696a6b6c6d6e6f7071727374757677"
               "78797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
               "909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7"
               "a8a9aaabacadaeaf",
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f1011121314151617"
               "18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
               "303132333435363738393a3b3c3d3e3f4041424344454647"
               "48494a4b4c4d4e4f",
               /*msg_hex=*/
               "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacb"
               "cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7"
               "e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
               /*output_hex=*/
               "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe43056"
               "73ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed"
               "034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
           })},
          {{22, HkdfPrfParameters::HashType::kSha1},
           MakeHkdfPrfTestVector(HkdfPrfTestVectorParams{
               /*key_size_in_bytes=*/22,
               /*hash_type=*/HkdfPrfParameters::HashType::kSha1,
               /*salt_hex=*/std::nullopt,
               /*key_hex=*/"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
               /*msg_hex=*/"",
               /*output_hex=*/
               "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87"
               "e8df21d0ea00033de03984d34918",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<HkdfPrfTestVector>& CreateHkdfPrfTestVectors() {
  static const absl::NoDestructor<std::vector<HkdfPrfTestVector>> test_vectors(
      [] {
        std::vector<HkdfPrfTestVector> result;
        result.reserve(CreateHkdfPrfTestVectorsMap().size());
        for (const auto& [unused_params, test_vector] :
             CreateHkdfPrfTestVectorsMap()) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const HkdfPrfTestVector& GetHkdfPrfTestVector(
    int key_size_in_bytes, HkdfPrfParameters::HashType hash_type) {
  const HkdfPrfTestVectorMap& test_vectors_map = CreateHkdfPrfTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, hash_type));
  ABSL_CHECK(it != test_vectors_map.end())
      << "HkdfPrfTestVector not found for HKDF PRF key with size "
      << key_size_in_bytes << " and hash_type " << static_cast<int>(hash_type);
  return it->second;
}

}  // namespace crypto::tink::internal
