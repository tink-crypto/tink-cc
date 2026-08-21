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

#include "tink/aead/internal/testing/aes_gcm_siv_test_vectors.h"

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
#include "tink/aead/aes_gcm_siv_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

struct AesGcmSivTestVectorParams {
  int key_size_in_bytes ABSL_REQUIRE_EXPLICIT_INIT;
  AesGcmSivParameters::Variant variant;
  absl::string_view key_hex;
  absl::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeAesGcmSivTestVector(
    const AesGcmSivTestVectorParams& params) {
  absl::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(params.key_size_in_bytes, params.variant);
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<AesGcmSivKey> key =
      AesGcmSivKey::Create(*parameters,
                           RestrictedData(HexDecodeOrDie(params.key_hex),
                                          InsecureSecretKeyAccess::Get()),
                           params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<AesGcmSivKey>(*std::move(key)),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

using AesGcmSivTestVectorMap =
    absl::flat_hash_map<std::pair<int, AesGcmSivParameters::Variant>,
                        AeadTestVector>;

const AesGcmSivTestVectorMap& CreateAesGcmSivTestVectorsMap() {
  static const absl::NoDestructor<AesGcmSivTestVectorMap> test_vectors(
      AesGcmSivTestVectorMap{
          // Wycheproof test vector: tcId = 5 (128-bit key)
          {{16, AesGcmSivParameters::Variant::kNoPrefix},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmSivParameters::Variant::kNoPrefix,
               /*key_hex=*/"01000000000000000000000000000000",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "03000000000000000000000084e07e62ba83a6585417245d7ec413a9fe"
               "427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667cd86847bf61"
               "55ff",
           })},
          {{16, AesGcmSivParameters::Variant::kTink},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmSivParameters::Variant::kTink,
               /*key_hex=*/"01000000000000000000000000000000",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "010102030403000000000000000000000084e07e62ba83a6585417245d"
               "7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667c"
               "d86847bf6155ff",
           })},
          {{16, AesGcmSivParameters::Variant::kCrunchy},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/16,
               /*variant=*/AesGcmSivParameters::Variant::kCrunchy,
               /*key_hex=*/"01000000000000000000000000000000",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "000102030403000000000000000000000084e07e62ba83a6585417245d"
               "7ec413a9fe427d6315c09b57ce45f2e3936a94451a8e45dcd4578c667c"
               "d86847bf6155ff",
           })},
          // Wycheproof test vector: tcId = 80 (256-bit key)
          {{32, AesGcmSivParameters::Variant::kNoPrefix},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmSivParameters::Variant::kNoPrefix,
               /*key_hex=*/
               "010000000000000000000000000000000000000000000000000"
               "0000000000000",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0300000000000000000000004a6a9db4c8c6549201b9edb53006cba821"
               "ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006a976397632"
               "eb5d",
           })},
          {{32, AesGcmSivParameters::Variant::kTink},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmSivParameters::Variant::kTink,
               /*key_hex=*/
               "010000000000000000000000000000000000000000000000000"
               "0000000000000",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "01010203040300000000000000000000004a6a9db4c8c6549201b9edb5"
               "3006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006"
               "a976397632eb5d",
           })},
          {{32, AesGcmSivParameters::Variant::kCrunchy},
           MakeAesGcmSivTestVector(AesGcmSivTestVectorParams{
               /*key_size_in_bytes=*/32,
               /*variant=*/AesGcmSivParameters::Variant::kCrunchy,
               /*key_hex=*/
               "010000000000000000000000000000000000000000000000000"
               "0000000000000",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "0100000000000000000000000000000002000000000000000000000000"
               "000000",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "00010203040300000000000000000000004a6a9db4c8c6549201b9edb5"
               "3006cba821ec9cf850948a7c86c68ac7539d027fe819e63abcd020b006"
               "a976397632eb5d",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateAesGcmSivTestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateAesGcmSivTestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateAesGcmSivTestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetAesGcmSivTestVector(
    int key_size_in_bytes, AesGcmSivParameters::Variant variant) {
  const AesGcmSivTestVectorMap& test_vectors_map =
      CreateAesGcmSivTestVectorsMap();
  auto it = test_vectors_map.find(std::pair(key_size_in_bytes, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for AES-GCM-SIV key with size "
      << key_size_in_bytes << " and variant " << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
