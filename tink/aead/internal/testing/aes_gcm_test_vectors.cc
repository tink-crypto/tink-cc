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
               /*key_hex=*/"feffe9928665731c6d6a8f9467308308",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "cafebabefacedbaddecaf88842831ec2217774244b7221b784d0d49ce3aa"
               "212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
               "1ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6"
               "fab4",
           })},
          {{16, AesGcmParameters::Variant::kTink},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmParameters::Variant::kTink,
               /*key_hex=*/"feffe9928665731c6d6a8f9467308308",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304cafebabefacedbaddecaf88842831ec2217774244b7221b784"
               "d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a"
               "5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62c"
               "f35abd2ba6fab4",
           })},
          {{16, AesGcmParameters::Variant::kCrunchy},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmParameters::Variant::kCrunchy,
               /*key_hex=*/"feffe9928665731c6d6a8f9467308308",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304cafebabefacedbaddecaf88842831ec2217774244b7221b784"
               "d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a"
               "5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62c"
               "f35abd2ba6fab4",
           })},
          {{32, AesGcmParameters::Variant::kNoPrefix},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f946730"
               "8308",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a84427d643a"
               "8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
               "c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3"
               "cc6c",
           })},
          {{32, AesGcmParameters::Variant::kTink},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f946730"
               "8308",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a"
               "84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b"
               "1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec"
               "1a502270e3cc6c",
           })},
          {{32, AesGcmParameters::Variant::kCrunchy},
           MakeAesGcmTestVector(AesGcmTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmParameters::Variant::kCrunchy,
               /*key_hex=*/
               "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f946730"
               "8308",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a31"
               "8a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
               "1aafd255",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a"
               "84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b"
               "1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec"
               "1a502270e3cc6c",
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
