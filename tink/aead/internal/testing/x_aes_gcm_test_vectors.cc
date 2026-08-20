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

#include "tink/aead/internal/testing/x_aes_gcm_test_vectors.h"

#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

using XAesGcmTestVectorMap =
    absl::flat_hash_map<std::pair<int, XAesGcmParameters::Variant>,
                        AeadTestVector>;

struct XAesGcmTestVectorParams {
  int salt_size_in_bytes ABSL_REQUIRE_EXPLICIT_INIT;
  XAesGcmParameters::Variant variant;
  absl::string_view key_hex;
  std::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeXAesGcmTestVector(const XAesGcmTestVectorParams& params) {
  absl::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(params.variant, params.salt_size_in_bytes);
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<XAesGcmKey> key =
      XAesGcmKey::Create(*parameters,
                         RestrictedData(HexDecodeOrDie(params.key_hex),
                                        InsecureSecretKeyAccess::Get()),
                         params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<XAesGcmKey>(*std::move(key)),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

const XAesGcmTestVectorMap& CreateXAesGcmTestVectorsMap() {
  static const absl::NoDestructor<XAesGcmTestVectorMap> test_vectors(
      XAesGcmTestVectorMap{
          {{8, XAesGcmParameters::Variant::kNoPrefix},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/8,
               /*variant=*/XAesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0000000000000000000000000000000000000000ce10e0e15f77f06bb"
               "3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{8, XAesGcmParameters::Variant::kTink},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/8,
               /*variant=*/XAesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "01010203040000000000000000000000000000000000000000ce10e0e15"
               "f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{9, XAesGcmParameters::Variant::kNoPrefix},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/9,
               /*variant=*/XAesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "000000000000000000000000000000000000000000ce10e0e15f77f06bb"
               "3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{9, XAesGcmParameters::Variant::kTink},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/9,
               /*variant=*/XAesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304000000000000000000000000000000000000000000ce10e0e15"
               "f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{10, XAesGcmParameters::Variant::kNoPrefix},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/10,
               /*variant=*/XAesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "00000000000000000000000000000000000000000000ce10e0e15f77f06"
               "bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{10, XAesGcmParameters::Variant::kTink},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/10,
               /*variant=*/XAesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "010102030400000000000000000000000000000000000000000000ce10e0"
               "e15f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{11, XAesGcmParameters::Variant::kNoPrefix},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/11,
               /*variant=*/XAesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0000000000000000000000000000000000000000000000ce10e0e15f77f0"
               "6bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{11, XAesGcmParameters::Variant::kTink},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/11,
               /*variant=*/XAesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "01010203040000000000000000000000000000000000000000000000ce10"
               "e0e15f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008f"
               "b",
           })},
          {{12, XAesGcmParameters::Variant::kNoPrefix},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/12,
               /*variant=*/XAesGcmParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "000000000000000000000000000000000000000000000000ce10e0e15"
               "f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a116b6008fb",
           })},
          {{12, XAesGcmParameters::Variant::kTink},
           MakeXAesGcmTestVector(XAesGcmTestVectorParams{
               /*salt_size_in_bytes=*/12,
               /*variant=*/XAesGcmParameters::Variant::kTink,
               /*key_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191"
               "a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1"
               "c1d1e1f",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "010102030400000000000000000000000000000000000000000000000"
               "0ce10e0e15f77f06bb3b7d3e691238e8ec434eb05581e7d0bbd603a11"
               "6b6008fb",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateXAesGcmTestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateXAesGcmTestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateXAesGcmTestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetXAesGcmTestVector(int salt_size_in_bytes,
                                           XAesGcmParameters::Variant variant) {
  const XAesGcmTestVectorMap& test_vectors_map = CreateXAesGcmTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(salt_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for X-AES-GCM key with size "
      << salt_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
