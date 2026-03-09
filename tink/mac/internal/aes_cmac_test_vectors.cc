// Copyright 2017 Google LLC
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

#include "tink/mac/internal/aes_cmac_test_vectors.h"

#include <vector>

#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::HexDecodeOrDie;

std::vector<TinkAesCmacTestVector> AesCmacTestVectors() {
  SecretKeyAccessToken ska = InsecureSecretKeyAccess::Get();
  PartialKeyAccessToken pka = GetPartialKeyAccess();
  return std::vector<TinkAesCmacTestVector>{
      // From Java AesCmacTestUtil
      {"RFC_TEST_VECTOR_0",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie(""), HexDecodeOrDie("bb1d6929e95937287fa37d129b756746")},
      // From Java AesCmacTestUtil
      {"RFC_TEST_VECTOR_1",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac"
                      "45af8e5130c81c46a35ce411"),
       HexDecodeOrDie("dfa66747de9ae63030ca32611497c827")},
      // From Java AesCmacTestUtil
      {"RFC_TEST_VECTOR_2",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie(
           "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c"
           "81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"),
       HexDecodeOrDie("51f0bebf7e3b9d92fc49741779363cfe")},
      // From Java AesCmacTestUtil
      {"NOT_OVERFLOWING_INTERNAL_STATE",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("aaaaaa"),
       HexDecodeOrDie("97268151a23fcd035a2dd0573d84e6ba")},
      // From Java AesCmacTestUtil
      {"FILL_UP_EXACTLY_INTERNAL_STATE",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
       HexDecodeOrDie("70e4648706483f8c5e8e2fab7b190c08")},
      // From Java AesCmacTestUtil
      {"FILL_UP_EXACTLY_INTERNAL_STATE_TWICE",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie(
           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
       HexDecodeOrDie("219db2ebac5416dc2b0d8afcb666fb7a")},
      // From Java AesCmacTestUtil
      {"OVERFLOW_INTERNAL_STATE_ONCE",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
       HexDecodeOrDie("0336c9c4bf8f1bc219b017292af24358")},
      // From Java AesCmacTestUtil
      {"OVERFLOW_INTERNAL_STATE_TWICE",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("611a1ededd3dfff548ed80b7fd10c0ba")},
      // From Java AesCmacTestUtil
      {"SHORTER_TAG",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/15,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("611a1ededd3dfff548ed80b7fd10c0")},
      // From Java AesCmacTestUtil
      {"TAG_WITH_KEY_PREFIX_TYPE_LEGACY",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kLegacy)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/1877, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("00000007554816512e20d15db74f1de942d86a2f7b")},
      // From Java AesCmacTestUtil
      {"TAG_WITH_KEY_PREFIX_TYPE_TINK",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kTink)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/1877, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("0100000755611a1ededd3dfff548ed80b7fd10c0ba")},
      {"TAG_WITH_KEY_PREFIX_TYPE_CRUNCHY",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 16,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kCrunchy)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/1877, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("0000000755611a1ededd3dfff548ed80b7fd10c0ba")},
      {"LONG_KEY_TEST_VECTOR",
       AesCmacKey::Create(
           AesCmacParameters::Create(/* key_size_in_bytes = */ 32,
                                     /*cryptographic_tag_size_in_bytes=*/16,
                                     AesCmacParameters::Variant::kNoPrefix)
               .value(),
           RestrictedData(HexDecodeOrDie("00112233445566778899aabbccddeeff00112"
                                         "233445566778899aabbccddeeff"),
                          ska),
           /*id_requirement=*/absl::nullopt, pka)
           .value(),
       HexDecodeOrDie("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                      "bbbbbbbbbbbbbb"),
       HexDecodeOrDie("139fce15a6f4a281ad22458d3d3cac26")},
  };
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
