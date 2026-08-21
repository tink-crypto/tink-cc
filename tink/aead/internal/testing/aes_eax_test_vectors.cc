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

#include "tink/aead/internal/testing/aes_eax_test_vectors.h"

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
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct AesEaxTestVectorParams {
  int key_size_in_bytes;
  AesEaxParameters::Variant variant;
  absl::string_view key_hex;
  std::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeAesEaxTestVector(const AesEaxTestVectorParams& params) {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(params.key_size_in_bytes)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(16)
          .SetVariant(params.variant)
          .Build();
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<AesEaxKey> key =
      AesEaxKey::Create(*parameters,
                        RestrictedData(HexDecodeOrDie(params.key_hex),
                                       InsecureSecretKeyAccess::Get()),
                        params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<AesEaxKey>(*std::move(key)),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

using AesEaxTestVectorMap =
    absl::flat_hash_map<std::pair<int, AesEaxParameters::Variant>,
                        AeadTestVector>;

const AesEaxTestVectorMap& CreateAesEaxTestVectorsMap() {
  static const absl::NoDestructor<AesEaxTestVectorMap> test_vectors(
      AesEaxTestVectorMap{
          // Wycheproof test vector: tcId = 1 (128-bit key)
          {{16, AesEaxParameters::Variant::kNoPrefix},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesEaxParameters::Variant::kNoPrefix,
               /*key_hex=*/"233952dee4d5ed5f9b9c6d6ff80ff478",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/"",
               /*associated_data_hex=*/"6bfb914fd07eae6b",
               /*ciphertext_hex=*/
               "62ec67f9c3a4a407fcb2a8c49031a8b3e037830e8389f27b025a2d6527e79d"
               "01",
           })},
          {{16, AesEaxParameters::Variant::kTink},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesEaxParameters::Variant::kTink,
               /*key_hex=*/"233952dee4d5ed5f9b9c6d6ff80ff478",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/"",
               /*associated_data_hex=*/"6bfb914fd07eae6b",
               /*ciphertext_hex=*/
               "010102030462ec67f9c3a4a407fcb2a8c49031a8b3e037830e8389f27b025a"
               "2d6527e79d01",
           })},
          {{16, AesEaxParameters::Variant::kCrunchy},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesEaxParameters::Variant::kCrunchy,
               /*key_hex=*/"233952dee4d5ed5f9b9c6d6ff80ff478",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/"",
               /*associated_data_hex=*/"6bfb914fd07eae6b",
               /*ciphertext_hex=*/
               "000102030462ec67f9c3a4a407fcb2a8c49031a8b3e037830e8389f27b025a"
               "2d6527e79d01",
           })},
          // Wycheproof test vector: tcId = 114 (256-bit key)
          {{32, AesEaxParameters::Variant::kNoPrefix},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesEaxParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "7517c973a9de3614431e3198f4ddc0f8dc33862654649e9ff7838635bb2782"
               "31",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/"d17fbed25ad5f72477580b9e82a7b883",
               /*associated_data_hex=*/"e9ee894ad5b0781d",
               /*ciphertext_hex=*/
               "42f82085c08afd5b19a9491a79cd81190b70b24253b2e1c3ef1165925b5c5e"
               "5745009a2a101877ed70e58f2e5910004f",
           })},
          {{32, AesEaxParameters::Variant::kTink},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesEaxParameters::Variant::kTink,
               /*key_hex=*/
               "7517c973a9de3614431e3198f4ddc0f8dc33862654649e9ff7838635bb2782"
               "31",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/"d17fbed25ad5f72477580b9e82a7b883",
               /*associated_data_hex=*/"e9ee894ad5b0781d",
               /*ciphertext_hex=*/
               "010102030442f82085c08afd5b19a9491a79cd81190b70b24253b2e1c3ef11"
               "65925b5c5e5745009a2a101877ed70e58f2e5910004f",
           })},
          {{32, AesEaxParameters::Variant::kCrunchy},
           MakeAesEaxTestVector(AesEaxTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesEaxParameters::Variant::kCrunchy,
               /*key_hex=*/
               "7517c973a9de3614431e3198f4ddc0f8dc33862654649e9ff7838635bb2782"
               "31",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/"d17fbed25ad5f72477580b9e82a7b883",
               /*associated_data_hex=*/"e9ee894ad5b0781d",
               /*ciphertext_hex=*/
               "000102030442f82085c08afd5b19a9491a79cd81190b70b24253b2e1c3ef11"
               "65925b5c5e5745009a2a101877ed70e58f2e5910004f",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateAesEaxTestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateAesEaxTestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateAesEaxTestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetAesEaxTestVector(int key_size_in_bytes,
                                          AesEaxParameters::Variant variant) {
  const AesEaxTestVectorMap& test_vectors_map = CreateAesEaxTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for AES-EAX key with size "
      << key_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
