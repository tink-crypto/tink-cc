// Copyright 2026 Google LLC
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

#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct AesGcmTestVectorParams {
  int key_size_in_bytes;
  AesGcmParameters::Variant variant;
  absl::string_view key_hex;
  absl::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeAesGcmTestVector(const AesGcmTestVectorParams& params) {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(params.key_size_in_bytes)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(params.variant)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<AesGcmKey> key =
      AesGcmKey::Create(*parameters,
                        RestrictedData(HexDecodeOrDie(params.key_hex),
                                       InsecureSecretKeyAccess::Get()),
                        params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<AesGcmKey>(*key),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

using AesGcmTestVectorMap =
    absl::flat_hash_map<std::pair<int, AesGcmParameters::Variant>,
                        AeadTestVector>;

const AesGcmTestVectorMap& CreateAesGcmTestVectorsMap() {
  static const absl::NoDestructor<AesGcmTestVectorMap> test_vectors(
      AesGcmTestVectorMap{
          {{16, AesGcmParameters::Variant::kNoPrefix},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/"5b9604fe14eadba931b0ccf3484344dd",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "001c4021235b8cf973a21680199d7010f3c5f4b069d80d24177d6118d0cc"
               "ec0c5ec76985cb961608670b86a8a53ae63ea25ebcbbd84197db3ea8003f"
               "0b2f5673620f4f9ffa3d339e144a2b251a37c95cf89617bdf75ec7a6ec0b"
               "2b8003f5db9bbce6092db560a6a02b37c0500bf8db9a8ee88f910ea098ce"
               "1b29a21e64177894a86496a32431cf4663efd07fa918b958c2b5ecceca2d"
               "f5da8f8df4ea85b46e3cb5ca16c1fb854ec7fb9217b1897f2596ea35ca3b"
               "bba0fb69c9b4e9f50f2ff4ee9f3d9dca77ab7d9f7831f2dcfaafb1dfc3ea"
               "1db2418e24fa2ebfb6b00b0ef8f9d784a0d9e26ffb54cb43dbab3cf1b294"
               "3e88fa2cc45b0a3c9b7dafcfaae00c88bc61ce02b9264c8d5fe6ca2df4da"
               "fb1df4caef1db17ae69fb3de6b9a89c9339ff7b065ff",
           })},
          {{16, AesGcmParameters::Variant::kTink},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmParameters::Variant::kTink,
               /*key_hex=*/"5b9604fe14eadba931b0ccf3484344dd",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304001c4021235b8cf973a21680199d7010f3c5f4b069d80d2417"
               "7d6118d0ccec0c5ec76985cb961608670b86a8a53ae63ea25ebcbbd84197"
               "db3ea8003f0b2f5673620f4f9ffa3d339e144a2b251a37c95cf89617bdf7"
               "5ec7a6ec0b2b8003f5db9bbce6092db560a6a02b37c0500bf8db9a8ee88f"
               "910ea098ce1b29a21e64177894a86496a32431cf4663efd07fa918b958c2"
               "b5ecceca2df5da8f8df4ea85b46e3cb5ca16c1fb854ec7fb9217b1897f25"
               "96ea35ca3bbba0fb69c9b4e9f50f2ff4ee9f3d9dca77ab7d9f7831f2dcfa"
               "afb1dfc3ea1db2418e24fa2ebfb6b00b0ef8f9d784a0d9e26ffb54cb43db"
               "abab3cf1b2943e88fa2cc45b0a3c9b7dafcfaae00c88bc61ce02b9264c8d"
               "5fe6ca2df4dafb1df4caef1db17ae69fb3de6b9a89c9339ff7b065ff",
           })},
          {{16, AesGcmParameters::Variant::kCrunchy},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmParameters::Variant::kCrunchy,
               /*key_hex=*/"5b9604fe14eadba931b0ccf3484344dd",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304001c4021235b8cf973a21680199d7010f3c5f4b069d80d2417"
               "7d6118d0ccec0c5ec76985cb961608670b86a8a53ae63ea25ebcbbd84197"
               "db3ea8003f0b2f5673620f4f9ffa3d339e144a2b251a37c95cf89617bdf7"
               "5ec7a6ec0b2b8003f5db9bbce6092db560a6a02b37c0500bf8db9a8ee88f"
               "910ea098ce1b29a21e64177894a86496a32431cf4663efd07fa918b958c2"
               "b5ecceca2df5da8f8df4ea85b46e3cb5ca16c1fb854ec7fb9217b1897f25"
               "96ea35ca3bbba0fb69c9b4e9f50f2ff4ee9f3d9dca77ab7d9f7831f2dcfa"
               "afb1dfc3ea1db2418e24fa2ebfb6b00b0ef8f9d784a0d9e26ffb54cb43db"
               "abab3cf1b2943e88fa2cc45b0a3c9b7dafcfaae00c88bc61ce02b9264c8d"
               "5fe6ca2df4dafb1df4caef1db17ae69fb3de6b9a89c9339ff7b065ff",
           })},
          {{32, AesGcmParameters::Variant::kNoPrefix},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1"
               "e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000000000000000000000000000000000000000000000000000000000000"
               "0000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "000000000000000000000000cea7403d4d606b6e074ec5d3baf39d18"
               "9a4a2579529301bcfb71c78d4060f52c",
           })},
          {{32, AesGcmParameters::Variant::kTink},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1"
               "e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000000000000000000000000000000000000000000000000000000000000"
               "0000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304000000000000000000000000cea7403d4d606b6e074ec5d3ba"
               "f39d189a4a2579529301bcfb71c78d4060f52c",
           })},
          {{32, AesGcmParameters::Variant::kCrunchy},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kCrunchy,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1"
               "e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000000000000000000000000000000000000000000000000000000000000"
               "0000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304000000000000000000000000cea7403d4d606b6e074ec5d3ba"
               "f39d189a4a2579529301bcfb71c78d4060f52c",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateAesGcmTestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    const AesGcmTestVectorMap& test_vectors_map = CreateAesGcmTestVectorsMap();
    std::vector<AeadTestVector> result;
    result.reserve(test_vectors_map.size());
    for (const auto& [unused_params, test_vector] : test_vectors_map) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetAesGcmTestVector(int key_size_in_bytes,
                                          AesGcmParameters::Variant variant) {
  const AesGcmTestVectorMap& test_vectors_map = CreateAesGcmTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for AES-GCM key with size "
      << key_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
