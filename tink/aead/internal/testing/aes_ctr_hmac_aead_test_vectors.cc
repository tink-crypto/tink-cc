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

#include "tink/aead/internal/testing/aes_ctr_hmac_aead_test_vectors.h"

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
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct AesCtrHmacAeadTestVectorParams {
  int aes_key_size_in_bytes;
  AesCtrHmacAeadParameters::Variant variant;
  absl::string_view aes_key_hex;
  absl::string_view hmac_key_hex;
  std::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeAesCtrHmacAeadTestVector(
    const AesCtrHmacAeadTestVectorParams& params) {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(params.aes_key_size_in_bytes)
          .SetHmacKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(params.variant)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*parameters)
          .SetAesKeyBytes(RestrictedData(HexDecodeOrDie(params.aes_key_hex),
                                         InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(RestrictedData(HexDecodeOrDie(params.hmac_key_hex),
                                          InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(params.id_requirement)
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<AesCtrHmacAeadKey>(*std::move(key)),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

using AesCtrHmacAeadTestVectorMap =
    absl::flat_hash_map<std::pair<int, AesCtrHmacAeadParameters::Variant>,
                        AeadTestVector>;

const AesCtrHmacAeadTestVectorMap& CreateAesCtrHmacAeadTestVectorsMap() {
  static const absl::NoDestructor<AesCtrHmacAeadTestVectorMap> test_vectors(
      AesCtrHmacAeadTestVectorMap{
          {{16, AesCtrHmacAeadParameters::Variant::kNoPrefix},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/16,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kNoPrefix,
               /*aes_key_hex=*/"2b7e151628aed2a6abf7158809cf4f3c",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff874d6191b620e3261bef686499"
               "0db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f"
               "09020db03eab1e031dda2fbe03d1792170a0f3009cee0d662e088bb97e"
               "14285adabfa9a37a90",
           })},
          {{16, AesCtrHmacAeadParameters::Variant::kTink},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/16,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kTink,
               /*aes_key_hex=*/"2b7e151628aed2a6abf7158809cf4f3c",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff874d6191b620e326"
               "1bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edb"
               "d5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee3db6"
               "4b84b5e0c653d9e84b80bbf23e1a",
           })},
          {{16, AesCtrHmacAeadParameters::Variant::kCrunchy},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/16,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kCrunchy,
               /*aes_key_hex=*/"2b7e151628aed2a6abf7158809cf4f3c",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff874d6191b620e326"
               "1bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edb"
               "d5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee3db6"
               "4b84b5e0c653d9e84b80bbf23e1a",
           })},
          {{24, AesCtrHmacAeadParameters::Variant::kNoPrefix},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/24,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kNoPrefix,
               /*aes_key_hex=*/
               "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff1abc932417521ca24f2b0459fe7e"
               "6e0b090339ec0aa6faefd5ccc2c6f4ce2896371c5e85d44d65a0b50a068d"
               "1e37a810f64e6a42054db0d4029ab204d9f58e3dc8e9c60362271f852e9f"
               "5073a9858af0",
           })},
          {{24, AesCtrHmacAeadParameters::Variant::kTink},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/24,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kTink,
               /*aes_key_hex=*/
               "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff1abc932417521ca24f"
               "2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce2896371c5e85d44d65"
               "a0b50a068d1e37a810f64e6a42054db0d4029ab204d9f58e3dc8e9c60362"
               "271f852e9f5073a9858af0",
           })},
          {{24, AesCtrHmacAeadParameters::Variant::kCrunchy},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/24,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kCrunchy,
               /*aes_key_hex=*/
               "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff1abc932417521ca24f"
               "2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce2896371c5e85d44d65"
               "a0b50a068d1e37a810f64e6a42054db0d4029ab204d9f58e3dc8e9c60362"
               "271f852e9f5073a9858af0",
           })},
          {{32, AesCtrHmacAeadParameters::Variant::kNoPrefix},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/32,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kNoPrefix,
               /*aes_key_hex=*/
               "603deb1015ca71be2b73aef0857d77811f352c073b6108"
               "d72d9810a30914dff4",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff601ec313775789a5b7a7f504bb"
               "f3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce870"
               "dc99a0c2d70ab708d4303b9e50130618a508b03d2abd97669d08479e0a"
               "e9ce2d56a319ca7f37",
           })},
          {{32, AesCtrHmacAeadParameters::Variant::kTink},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/32,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kTink,
               /*aes_key_hex=*/
               "603deb1015ca71be2b73aef0857d77811f352c073b6108"
               "d72d9810a30914dff4",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0101020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff601ec313775789a5"
               "b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa2"
               "3de94ce870dc99a0c2d70ab708d4303b9e50130618a508b03d2abd9755"
               "3bb79a952674e79eb00dca0a4309",
           })},
          {{32, AesCtrHmacAeadParameters::Variant::kCrunchy},
           MakeAesCtrHmacAeadTestVector(AesCtrHmacAeadTestVectorParams{
               /*aes_key_size_in_bytes=*/32,
               /*variant=*/AesCtrHmacAeadParameters::Variant::kCrunchy,
               /*aes_key_hex=*/
               "603deb1015ca71be2b73aef0857d77811f352c073b6108"
               "d72d9810a30914dff4",
               /*hmac_key_hex=*/
               "000102030405060708090a0b0c0d0e0f10111213141516"
               "1718191a1b1c1d1e1f",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45"
               "af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b"
               "417be66c3710",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0001020304f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff601ec313775789a5"
               "b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa2"
               "3de94ce870dc99a0c2d70ab708d4303b9e50130618a508b03d2abd9755"
               "3bb79a952674e79eb00dca0a4309",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateAesCtrHmacAeadTestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateAesCtrHmacAeadTestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateAesCtrHmacAeadTestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetAesCtrHmacAeadTestVector(
    int aes_key_size_in_bytes, AesCtrHmacAeadParameters::Variant variant) {
  const AesCtrHmacAeadTestVectorMap& test_vectors_map =
      CreateAesCtrHmacAeadTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(aes_key_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for AES-CTR-HMAC-AEAD key with AES key size "
      << aes_key_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
