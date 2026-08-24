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

#include "tink/aead/internal/testing/xchacha20_poly1305_test_vectors.h"

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
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using XChaCha20Poly1305TestVectorMap =
    absl::flat_hash_map<XChaCha20Poly1305Parameters::Variant, AeadTestVector>;

struct XChaCha20Poly1305TestVectorParams {
  XChaCha20Poly1305Parameters::Variant variant;
  absl::string_view key_hex;
  absl::optional<int> id_requirement;
  absl::string_view plaintext_hex;
  absl::string_view associated_data_hex;
  absl::string_view ciphertext_hex;
};

AeadTestVector MakeXChaCha20Poly1305TestVector(
    const XChaCha20Poly1305TestVectorParams& params) {
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params.variant,
      RestrictedData(HexDecodeOrDie(params.key_hex),
                     InsecureSecretKeyAccess::Get()),
      params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(key.status());
  return AeadTestVector(std::make_shared<XChaCha20Poly1305Key>(*key),
                        HexDecodeOrDie(params.plaintext_hex),
                        HexDecodeOrDie(params.associated_data_hex),
                        HexDecodeOrDie(params.ciphertext_hex));
}

const XChaCha20Poly1305TestVectorMap& CreateXChaCha20Poly1305TestVectorsMap() {
  static const absl::NoDestructor<XChaCha20Poly1305TestVectorMap> test_vectors(
      XChaCha20Poly1305TestVectorMap{
          // Wycheproof test vector: tcId = 66
          {XChaCha20Poly1305Parameters::Variant::kNoPrefix,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kNoPrefix,
               /*key_hex=*/
               "2ed460a56867ee1a2877a8f3d2d98fb886cfcc8913e31c3d08f42374ba37e"
               "bb1",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "318cc4bf151c3baaee5a783ec091ab618f2ecacf38c962ba9c32c323696c"
               "c94c",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "0140f2791eb81fd4b69edf2d9ba4b2d62eab1d296741583fd34c1778d105d"
               "0e80d429c86b879d52835cf8aebc5a04a9084cff1f9646e040aac8a68605a"
               "0567c559442342b764b964",
           })},
          {XChaCha20Poly1305Parameters::Variant::kTink,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kTink,
               /*key_hex=*/
               "2ed460a56867ee1a2877a8f3d2d98fb886cfcc8913e31c3d08f42374ba37e"
               "bb1",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "318cc4bf151c3baaee5a783ec091ab618f2ecacf38c962ba9c32c323696c"
               "c94c",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "01010203040140f2791eb81fd4b69edf2d9ba4b2d62eab1d296741583fd34"
               "c1778d105d0e80d429c86b879d52835cf8aebc5a04a9084cff1f9646e040a"
               "ac8a68605a0567c559442342b764b964",
           })},
          {XChaCha20Poly1305Parameters::Variant::kCrunchy,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kCrunchy,
               /*key_hex=*/
               "2ed460a56867ee1a2877a8f3d2d98fb886cfcc8913e31c3d08f42374ba37e"
               "bb1",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "318cc4bf151c3baaee5a783ec091ab618f2ecacf38c962ba9c32c323696c"
               "c94c",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "00010203040140f2791eb81fd4b69edf2d9ba4b2d62eab1d296741583fd34"
               "c1778d105d0e80d429c86b879d52835cf8aebc5a04a9084cff1f9646e040a"
               "ac8a68605a0567c559442342b764b964",
           })},
      });
  return *test_vectors;
}

}  // namespace

const std::vector<AeadTestVector>& CreateXChaCha20Poly1305TestVectors() {
  static const absl::NoDestructor<std::vector<AeadTestVector>> test_vectors([] {
    std::vector<AeadTestVector> result;
    result.reserve(CreateXChaCha20Poly1305TestVectorsMap().size());
    for (const auto& [unused_params, test_vector] :
         CreateXChaCha20Poly1305TestVectorsMap()) {
      result.push_back(test_vector);
    }
    return result;
  }());
  return *test_vectors;
}

const AeadTestVector& GetXChaCha20Poly1305TestVector(
    XChaCha20Poly1305Parameters::Variant variant) {
  const XChaCha20Poly1305TestVectorMap& test_vectors_map =
      CreateXChaCha20Poly1305TestVectorsMap();
  auto it = test_vectors_map.find(variant);
  ABSL_CHECK(it != test_vectors_map.end())
      << "AeadTestVector not found for XChaCha20-Poly1305 key with variant "
      << static_cast<int>(variant);
  return it->second;
}

}  // namespace crypto::tink::internal
