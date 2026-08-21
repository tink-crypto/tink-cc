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

#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"

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
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ChaCha20Poly1305TestVectorMap =
    absl::flat_hash_map<ChaCha20Poly1305Parameters::Variant, AeadTestVector>;

struct ChaCha20Poly1305TestVectorParams {
  ChaCha20Poly1305Parameters::Variant variant;
  absl::string_view key_hex;
  std::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeChaCha20Poly1305TestVector(
    const ChaCha20Poly1305TestVectorParams& params) {
  absl::StatusOr<ChaCha20Poly1305Parameters> parameters =
      ChaCha20Poly1305Parameters::Create(params.variant);
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<ChaCha20Poly1305Key> key = ChaCha20Poly1305Key::Create(
      params.variant,
      RestrictedData(HexDecodeOrDie(params.key_hex),
                     InsecureSecretKeyAccess::Get()),
      params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<ChaCha20Poly1305Key>(*key),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

const ChaCha20Poly1305TestVectorMap& CreateChaCha20Poly1305TestVectorsMap() {
  static const absl::NoDestructor<ChaCha20Poly1305TestVectorMap> test_vectors(
      ChaCha20Poly1305TestVectorMap{
          // Wycheproof test vector: tcId = 66
          {ChaCha20Poly1305Parameters::Variant::kNoPrefix,
           MakeChaCha20Poly1305TestVector(ChaCha20Poly1305TestVectorParams{
               /*variant=*/ChaCha20Poly1305Parameters::Variant::kNoPrefix,
               /*key_hex=*/
               "e1731d5854e1b70cb3ffe8b786a2b3ebf0994370954757b9dc8c7bc535463"
               "4a3",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "b9c554cbc36ac18ae897df7beecac1dbeb4eafa156bb60ce2e5d48f05715e"
               "678",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "72cfd90ef3026ca22b7e6e6aea29afa49d36e8760f5fe19723b9811ed5d51"
               "9934a440f5081ac430b953b0e21222541af46b86533c6b68d2ff108a7ea",
           })},
          {ChaCha20Poly1305Parameters::Variant::kTink,
           MakeChaCha20Poly1305TestVector(ChaCha20Poly1305TestVectorParams{
               /*variant=*/ChaCha20Poly1305Parameters::Variant::kTink,
               /*key_hex=*/
               "e1731d5854e1b70cb3ffe8b786a2b3ebf0994370954757b9dc8c7bc535463"
               "4a3",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "b9c554cbc36ac18ae897df7beecac1dbeb4eafa156bb60ce2e5d48f05715e"
               "678",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "010102030472cfd90ef3026ca22b7e6e6aea29afa49d36e8760f5fe19723b"
               "9811ed5d519934a440f5081ac430b953b0e21222541af46b86533c6b68d2f"
               "f108a7ea",
           })},
          {ChaCha20Poly1305Parameters::Variant::kCrunchy,
           MakeChaCha20Poly1305TestVector(ChaCha20Poly1305TestVectorParams{
               /*variant=*/ChaCha20Poly1305Parameters::Variant::kCrunchy,
               /*key_hex=*/
               "e1731d5854e1b70cb3ffe8b786a2b3ebf0994370954757b9dc8c7bc535463"
               "4a3",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "b9c554cbc36ac18ae897df7beecac1dbeb4eafa156bb60ce2e5d48f05715e"
               "678",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "000102030472cfd90ef3026ca22b7e6e6aea29afa49d36e8760f5fe19723b"
               "9811ed5d519934a440f5081ac430b953b0e21222541af46b86533c6b68d2f"
               "f108a7ea",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateChaCha20Poly1305TestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateChaCha20Poly1305TestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateChaCha20Poly1305TestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetChaCha20Poly1305TestVector(
    ChaCha20Poly1305Parameters::Variant variant) {
  const ChaCha20Poly1305TestVectorMap& test_vectors_map =
      CreateChaCha20Poly1305TestVectorsMap();
  auto it = test_vectors_map.find(variant);
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for ChaCha20-Poly1305 key with variant "
      << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
