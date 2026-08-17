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

using XChaCha20Poly1305TestVectorMap =
    absl::flat_hash_map<XChaCha20Poly1305Parameters::Variant, AeadTestVector>;

const XChaCha20Poly1305TestVectorMap& CreateXChaCha20Poly1305TestVectorsMap() {
  static const absl::NoDestructor<XChaCha20Poly1305TestVectorMap> test_vectors(
      XChaCha20Poly1305TestVectorMap{
          {XChaCha20Poly1305Parameters::Variant::kNoPrefix,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kNoPrefix,
               /*key_hex=*/
               "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7"
               "158809cf4f3c",
               /*id_requirement=*/std::nullopt,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "00000000000000000000000000000000000000000000000062f8b5a0ff8"
               "9c12b7be5cfd4df9ae1ccba586dbfcabf828a2a5e4d2576b5d9297a7371"
               "be96b34d9a5b39922a",
           })},
          {XChaCha20Poly1305Parameters::Variant::kTink,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kTink,
               /*key_hex=*/
               "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7"
               "158809cf4f3c",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "01010203040000000000000000000000000000000000000000000000006"
               "2f8b5a0ff89c12b7be5cfd4df9ae1ccba586dbfcabf828a2a5e4d2576b5"
               "d9297a7371be96b34d9a5b39922a",
           })},
          {XChaCha20Poly1305Parameters::Variant::kCrunchy,
           MakeXChaCha20Poly1305TestVector(XChaCha20Poly1305TestVectorParams{
               /*variant=*/XChaCha20Poly1305Parameters::Variant::kCrunchy,
               /*key_hex=*/
               "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7"
               "158809cf4f3c",
               /*id_requirement=*/0x01020304,
               /*plaintext_hex=*/
               "f1cc30e8ecdf0ec03a5204c2108cc013de8f0519445d45e14f62a8f49b34"
               "2e9e",
               /*associated_data_hex=*/"",
               /*ciphertext_hex=*/
               "00010203040000000000000000000000000000000000000000000000006"
               "2f8b5a0ff89c12b7be5cfd4df9ae1ccba586dbfcabf828a2a5e4d2576b5"
               "d9297a7371be96b34d9a5b39922a",
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
