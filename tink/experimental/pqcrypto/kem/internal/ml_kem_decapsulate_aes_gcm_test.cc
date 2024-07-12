// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_decapsulate_aes_gcm.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_KYBER
#include "openssl/experimental/kyber.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/config/global_registry.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/kem_decapsulate.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

AesGcmParameters CreateAes256GcmParameters() {
  CHECK_OK(AeadConfig::Register());

  util::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

TEST(MlKemDecapsulateAes256GcmTest, InvalidAesKeySize) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<AesGcmParameters> aes_128_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(aes_128_parameters, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, *aes_128_parameters).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("AES-GCM parameters are not compatible with ML-KEM")));
}

TEST(MlKemEncapsulateAes256GcmTest, InvalidIdRequirementForDerivedKey) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<AesGcmParameters> aes_tink_parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(aes_tink_parameters, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, *aes_tink_parameters).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Keys derived from an ML-KEM shared secret "
                         "must not have an ID requirement")));
}

TEST(MlKemDecapsulateAes256GcmTest, EncapsulateDecapsulateAeadWorks) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  // Exchange a key pair.
  util::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  util::StatusOr<KemEncapsulation> encapsulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  util::StatusOr<KeysetHandle> decapsulation =
      (*decapsulate)->Decapsulate(encapsulation->ciphertext);
  ASSERT_THAT(decapsulation, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> encaps_aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(encaps_aead, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      decapsulation->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  // Check that the AEAD primitives are compatible.
  util::StatusOr<std::string> ciphertext =
      (*encaps_aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  util::StatusOr<std::string> decrypted =
      (*decaps_aead)->Decrypt(*ciphertext, "associated data");
  EXPECT_THAT(decrypted, IsOkAndHolds("plaintext"));

  EXPECT_THAT(
      (*decaps_aead)->Decrypt(*ciphertext, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  // The AEAD primitives are also compatible for messages sent in the other
  // direction.
  util::StatusOr<std::string> ciphertext2 =
      (*decaps_aead)->Encrypt("plaintext 2", "associated data 2");
  ASSERT_THAT(ciphertext2, IsOk());

  util::StatusOr<std::string> decrypted2 =
      (*encaps_aead)->Decrypt(*ciphertext2, "associated data 2");
  EXPECT_THAT(decrypted2, IsOkAndHolds("plaintext 2"));

  EXPECT_THAT(
      (*encaps_aead)->Decrypt(*ciphertext2, "bad associated data").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemDecapsulateAes256GcmTest,
     WrongCiphertextDecapsulateAeadIsIncompatible) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  // Exchange a key pair.
  util::StatusOr<std::unique_ptr<KemEncapsulate>> encapsulate =
      NewMlKemEncapsulateAes256Gcm(private_key->GetPublicKey(),
                                   CreateAes256GcmParameters());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  // Exchange an encapsulation and derive AEAD primitives.
  util::StatusOr<KemEncapsulation> encapsulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(encapsulation, IsOk());

  util::StatusOr<KeysetHandle> decapsulation =
      (*decapsulate)
          ->Decapsulate(absl::StrCat(private_key->GetOutputPrefix(),
                                     std::string(KYBER_CIPHERTEXT_BYTES, 'A')));
  ASSERT_THAT(decapsulation, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> encaps_aead =
      encapsulation->keyset_handle.GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(encaps_aead, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      decapsulation->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  // Check that the AEAD primitives are incompatible, in either direction.
  util::StatusOr<std::string> ciphertext =
      (*encaps_aead)->Encrypt("plaintext", "associated data");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_THAT((*decaps_aead)->Decrypt(*ciphertext, "associated data").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  util::StatusOr<std::string> ciphertext2 =
      (*decaps_aead)->Encrypt("plaintext 2", "associated data 2");
  ASSERT_THAT(ciphertext2, IsOk());

  EXPECT_THAT(
      (*encaps_aead)->Decrypt(*ciphertext2, "associated data 2").status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlKemDecapsulateAes256GcmTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters())
          .status(),
      StatusIs(absl::StatusCode::kInternal));
}

// Test vector based on the round 3 version.
TEST(MlKemRawDecapsulateBoringSslTest, TestVectorEncapsulateDecapsulate) {
  constexpr absl::string_view kHexPublicKey =
      "A72C2D9C843EE9F8313ECC7F86D6294D59159D9A879A542E260922ADF999051CC45200C9"
      "FFDB60449C49465979272367C083A7D6267A3ED7A7FD47957C219327F7CA73A4007E1627"
      "F00B11CC80573C15AEE6640FB8562DFA6B240CA0AD351AC4AC155B96C14C8AB13DD262CD"
      "FD51C4BB5572FD616553D17BDD430ACBEA3E95F0B698D66990AB51E5D03783A8B3D278A5"
      "720454CF9695CFDCA08485BA099C51CD92A7EA7587C1D15C28E609A81852601B06040106"
      "79AA482D51261EC36E36B8719676217FD74C54786488F4B4969C05A8BA27CA3A77CCE73B"
      "965923CA554E422B9B61F4754641608AC16C9B8587A32C1C5DD788F88B36B717A4696563"
      "5DEB67F45B129B99070909C93EB80B42C2B3F3F70343A7CF37E8520E7BCFC416ACA4F18C"
      "7981262BA2BFC756AE03278F0EC66DC2057696824BA6769865A601D7148EF6F54E5AF568"
      "6AA2906F994CE38A5E0B938F239007003022C03392DF3401B1E4A3A7EBC6161449F73374"
      "C8B0140369343D9295FDF511845C4A46EBAAB6CA5492F6800B98C0CC803653A4B1D6E6AA"
      "ED1932BACC5FEFAA818BA502859BA5494C5F5402C8536A9C4C1888150617F80098F6B2A9"
      "9C39BC5DC7CF3B5900A21329AB59053ABAA64ED163E859A8B3B3CA3359B750CCC3E710C7"
      "AC43C8191CB5D68870C06391C0CB8AEC72B897AC6BE7FBAACC676ED66314C83630E89448"
      "C88A1DF04ACEB23ABF2E409EF333C622289C18A2134E650C45257E47475FA33AA537A5A8"
      "F7680214716C50D470E3284963CA64F54677AEC54B5272162BF52BC8142E1D4183FC0174"
      "54A6B5A496831759064024745978CBD51A6CEDC8955DE4CC6D363670A47466E82BE5C236"
      "03A17BF22ACDB7CC984AF08C87E14E27753CF587A8EC3447E62C649E887A67C36C9CE987"
      "21B697213275646B194F36758673A8ED11284455AFC7A8529F69C97A3C2D7B8C636C0BA5"
      "5614B768E624E712930F776169B01715725351BC74B47395ED52B25A1313C95164814C34"
      "C979CBDFAB85954662CAB485E75087A98CC74BB82CA2D1B5BF2803238480638C40E90B43"
      "C7460E7AA917F010151FAB1169987B372ABB59271F7006C24E60236B84B9DDD600623704"
      "254617FB498D89E58B0368BCB2103E79353EB587860C1422E476162E425BC2381DB82C65"
      "92737E1DD602864B0167A71EC1F223305C02FE25052AF2B3B5A55A0D7A2022D9A798DC0C"
      "5874A98702AAF4054C5D80338A5248B5B7BD09C53B5E2A084B047D277A861B1A73BB5148"
      "8DE04EF573C85230A0470B73175C9FA50594F66A5F50B4150054C93B68186F8B5CBC4931"
      "6C8548A642B2B36A1D454C7489AC33B2D2CE6668096782A2C1E0866D21A65E16B585E7AF"
      "8618BDF3184C1986878508917277B93E10706B1614972B2A94C7310FE9C708C231A1A8AC"
      "8D9314A529A97F469BF64962D820648443099A076D55D4CEA824A58304844F99497C10A2"
      "5148618A315D72CA857D1B04D575B94F85C01D19BEF211BF0AA3362E7041FD16596D808E"
      "867B44C4C00D1CDA3418967717F147D0EB21B42AAEE74AC35D0B92414B958531AADF463E"
      "C6305AE5ECAF79174002F26DDECC813BF32672E8529D95A4E730A7AB4A3E8F8A8AF979A6"
      "65EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B53922";
  constexpr absl::string_view kHexPrivateKey =
      "07638FB69868F3D320E5862BD96933FEB311B362093C9B5D50170BCED43F1B536D9A204B"
      "B1F22695950BA1F2A9E8EB828B284488760B3FC84FABA04275D5628E39C5B2471374283C"
      "503299C0AB49B66B8BBB56A4186624F919A2BA59BB08D8551880C2BEFC4F87F25F59AB58"
      "7A79C327D792D54C974A69262FF8A78938289E9A87B688B083E0595FE218B6BB1505941C"
      "E2E81A5A64C5AAC60417256985349EE47A52420A5F97477B7236AC76BC70E8288729287E"
      "E3E34A3DBC3683C0B7B10029FC203418537E7466BA6385A8FF301EE12708F82AAA1E380F"
      "C7A88F8F205AB7E88D7E95952A55BA20D09B79A47141D62BF6EB7DD307B08ECA13A5BC5F"
      "6B68581C6865B27BBCDDAB142F4B2CBFF488C8A22705FAA98A2B9EEA3530C76662335CC7"
      "EA3A00777725EBCCCD2A4636B2D9122FF3AB77123CE0883C1911115E50C9E8A94194E48D"
      "D0D09CFFB3ADCD2C1E92430903D07ADBF00532031575AA7F9E7B5A1F3362DEC936D4043C"
      "05F2476C07578BC9CBAF2AB4E382727AD41686A96B2548820BB03B32F11B2811AD62F489"
      "E951632ABA0D1DF89680CC8A8B53B481D92A68D70B4EA1C3A6A561C0692882B5CA8CC942"
      "A8D495AFCB06DE89498FB935B775908FE7A03E324D54CC19D4E1AABD3593B38B19EE1388"
      "FE492B43127E5A504253786A0D69AD32601C28E2C88504A5BA599706023A61363E17C6B9"
      "BB59BDC697452CD059451983D738CA3FD034E3F5988854CA05031DB09611498988197C6B"
      "30D258DFE26265541C89A4B31D6864E9389B03CB74F7EC4323FB9421A4B9790A26D17B03"
      "98A26767350909F84D57B6694DF830664CA8B3C3C03ED2AE67B89006868A68527CCD6664"
      "59AB7F056671000C6164D3A7F266A14D97CBD7004D6C92CACA770B844A4FA9B182E7B18C"
      "A885082AC5646FCB4A14E1685FEB0C9CE3372AB95365C04FD83084F80A23FF10A05BF15F"
      "7FA5ACC6C0CB462C33CA524FA6B8BB359043BA68609EAA2536E81D08463B19653B5435BA"
      "946C9ADDEB202B04B031CC960DCC12E4518D428B32B257A4FC7313D3A7980D80082E934F"
      "9D95C32B0A0191A23604384DD9E079BBBAA266D14C3F756B9F2133107433A4E83FA71872"
      "82A809203A4FAF841851833D121AC383843A5E55BC2381425E16C7DB4CC9AB5C1B0D91A4"
      "7E2B8DE0E582C86B6B0D907BB360B97F40AB5D038F6B75C814B27D9B968D419832BC8C2B"
      "EE605EF6E5059D33100D90485D378450014221736C07407CAC260408AA64926619788B86"
      "01C2A752D1A6CBF820D7C7A04716203225B3895B9342D147A8185CFC1BB65BA06B414233"
      "9903C0AC4651385B45D98A8B19D28CD6BAB088787F7EE1B12461766B43CBCCB96434427D"
      "93C065550688F6948ED1B5475A425F1B85209D061C08B56C1CC069F6C0A7C6F29358CAB9"
      "11087732A649D27C9B98F9A48879387D9B00C25959A71654D6F6A946164513E47A75D005"
      "986C2363C09F6B537ECA78B9303A5FA457608A586A653A347DB04DFCC19175B3A3011725"
      "36062A658A95277570C8852CA8973F4AE123A334047DD711C8927A634A03388A527B034B"
      "F7A8170FA702C1F7C23EC32D18A2374890BE9C787A9409C82D192C4BB705A2F996CE405D"
      "A72C2D9C843EE9F8313ECC7F86D6294D59159D9A879A542E260922ADF999051CC45200C9"
      "FFDB60449C49465979272367C083A7D6267A3ED7A7FD47957C219327F7CA73A4007E1627"
      "F00B11CC80573C15AEE6640FB8562DFA6B240CA0AD351AC4AC155B96C14C8AB13DD262CD"
      "FD51C4BB5572FD616553D17BDD430ACBEA3E95F0B698D66990AB51E5D03783A8B3D278A5"
      "720454CF9695CFDCA08485BA099C51CD92A7EA7587C1D15C28E609A81852601B06040106"
      "79AA482D51261EC36E36B8719676217FD74C54786488F4B4969C05A8BA27CA3A77CCE73B"
      "965923CA554E422B9B61F4754641608AC16C9B8587A32C1C5DD788F88B36B717A4696563"
      "5DEB67F45B129B99070909C93EB80B42C2B3F3F70343A7CF37E8520E7BCFC416ACA4F18C"
      "7981262BA2BFC756AE03278F0EC66DC2057696824BA6769865A601D7148EF6F54E5AF568"
      "6AA2906F994CE38A5E0B938F239007003022C03392DF3401B1E4A3A7EBC6161449F73374"
      "C8B0140369343D9295FDF511845C4A46EBAAB6CA5492F6800B98C0CC803653A4B1D6E6AA"
      "ED1932BACC5FEFAA818BA502859BA5494C5F5402C8536A9C4C1888150617F80098F6B2A9"
      "9C39BC5DC7CF3B5900A21329AB59053ABAA64ED163E859A8B3B3CA3359B750CCC3E710C7"
      "AC43C8191CB5D68870C06391C0CB8AEC72B897AC6BE7FBAACC676ED66314C83630E89448"
      "C88A1DF04ACEB23ABF2E409EF333C622289C18A2134E650C45257E47475FA33AA537A5A8"
      "F7680214716C50D470E3284963CA64F54677AEC54B5272162BF52BC8142E1D4183FC0174"
      "54A6B5A496831759064024745978CBD51A6CEDC8955DE4CC6D363670A47466E82BE5C236"
      "03A17BF22ACDB7CC984AF08C87E14E27753CF587A8EC3447E62C649E887A67C36C9CE987"
      "21B697213275646B194F36758673A8ED11284455AFC7A8529F69C97A3C2D7B8C636C0BA5"
      "5614B768E624E712930F776169B01715725351BC74B47395ED52B25A1313C95164814C34"
      "C979CBDFAB85954662CAB485E75087A98CC74BB82CA2D1B5BF2803238480638C40E90B43"
      "C7460E7AA917F010151FAB1169987B372ABB59271F7006C24E60236B84B9DDD600623704"
      "254617FB498D89E58B0368BCB2103E79353EB587860C1422E476162E425BC2381DB82C65"
      "92737E1DD602864B0167A71EC1F223305C02FE25052AF2B3B5A55A0D7A2022D9A798DC0C"
      "5874A98702AAF4054C5D80338A5248B5B7BD09C53B5E2A084B047D277A861B1A73BB5148"
      "8DE04EF573C85230A0470B73175C9FA50594F66A5F50B4150054C93B68186F8B5CBC4931"
      "6C8548A642B2B36A1D454C7489AC33B2D2CE6668096782A2C1E0866D21A65E16B585E7AF"
      "8618BDF3184C1986878508917277B93E10706B1614972B2A94C7310FE9C708C231A1A8AC"
      "8D9314A529A97F469BF64962D820648443099A076D55D4CEA824A58304844F99497C10A2"
      "5148618A315D72CA857D1B04D575B94F85C01D19BEF211BF0AA3362E7041FD16596D808E"
      "867B44C4C00D1CDA3418967717F147D0EB21B42AAEE74AC35D0B92414B958531AADF463E"
      "C6305AE5ECAF79174002F26DDECC813BF32672E8529D95A4E730A7AB4A3E8F8A8AF979A6"
      "65EAFD465FC64A0C5F8F3F9003489415899D59A543D8208C54A3166529B53922D4EC143B"
      "50F01423B177895EDEE22BB739F647ECF85F50BC25EF7B5A725DEE868626ED79D4511408"
      "00E03B59B956F8210E556067407D13DC90FA9E8B872BFB8F";
  constexpr absl::string_view kHexKemCiphertextWithTinkPrefix =
      "0141424344B52C56B92A4B7CE9E4CB7C5B1B163167A8A1675B2FDEF84A5B67CA15DB694C"
      "9F11BD027C30AE22EC921A1D911599AF0585E48D20DA70DF9F39E32EF95D4C8F44BFEFDA"
      "A5DA64F1054631D04D6D3CFD0A540DD7BA3886E4B5F13E878788604C95C096EAB3919F42"
      "7521419A946C26CC041475D7124CDC01D0373E5B09C7A70603CFDB4FB3405023F2264DC3"
      "F983C4FC02A2D1B268F2208A1F6E2A6209BFF12F6F465F0B069C3A7F84F606D8A9406400"
      "3D6EC114C8E808D3053884C1D5A142FBF20112EB360FDA3F0F28B172AE50F5E7D83801FB"
      "3F0064B687187074BD7FE30EDDAA334CF8FC04FA8CED899CEADE4B4F28B68372BAF98FF4"
      "82A415B731155B75CEB976BE0EA0285BA01A27F1857A8FB377A3AE0C23B2AA9A079BFABF"
      "F0D5B2F1CD9B718BEA03C42F343A39B4F142D01AD8ACBB50E38853CF9A50C8B44C3CF671"
      "A4A9043B26DDBB24959AD6715C08521855C79A23B9C3D6471749C40725BDD5C2776D43AE"
      "D20204BAA141EFB3304917474B7F9F7A4B08B1A93DAED98C67495359D37D67F7438BEE5E"
      "43585634B26C6B3810D7CDCBC0F6EB877A6087E68ACB8480D3A8CF6900447E49B417F15A"
      "53B607A0E216B855970D37406870B4568722DA77A4084703816784E2F16BED18996532C5"
      "D8B7F5D214464E5F3F6E905867B0CE119E252A66713253544685D208E1723908A0CE9783"
      "4652E08AE7BDC881A131B73C71E84D20D68FDEFF4F5D70CD1AF57B78E3491A9865942321"
      "800A203C05ED1FEEB5A28E584E19F6535E7F84E4A24F84A72DCAF5648B4A4235DD664464"
      "482F03176E888C28BFC6C1CB238CFFA35A321E71791D9EA8ED0878C61121BF8D2A4AB2C1"
      "A5E120BC40ABB1892D1715090A0EE48252CA297A99AA0E510CF26B1ADD06CA543E1C5D6B"
      "DCD3B9C585C8538045DB5C252EC3C8C3C954D9BE5907094A894E60EAB43538CFEE82E8FF"
      "C0791B0D0F43AC1627830A61D56DAD96C62958B0DE780B78BD47A604550DAB83FFF227C3"
      "24049471F35248CFB849B25724FF704D5277AA352D550958BE3B237DFF473EC2ADBAEA48"
      "CA2658AEFCC77BBD4264AB374D70EAE5B964416CE8226A7E3255A0F8D7E2ADCA062BCD6D"
      "78D60D1B32E11405BE54B66EF0FDDD567702A3BCCFEDE3C584701269ED14809F06F89683"
      "56BB9267FE86E514252E88BB5C30A7ECB3D0E621021EE0FBF7871B09342BF84F55C97EAF"
      "86C48189C7FF4DF389F077E2806E5FA73B3E9458A16C7E275F4F602275580EB7B7135FB5"
      "37FA0CD95D6EA58C108CD8943D70C1643111F4F01CA8A8276A902666ED81B78D168B006F"
      "16AAA3D8E4CE4F4D0FB0997E41AEFFB5B3DAA838732F357349447F387776C793C0479DE9"
      "E99498CC356FDB0075A703F23C55D47B550EC89B02ADE89329086A50843456FEDC3788AC"
      "8D97233C54560467EE1D0F024B18428F0D73B30E19F5C63B9ABF11415BEA4D0170130BAA"
      "BD33C05E6524E5FB5581B22B0433342248266D0F1053B245CC2462DC44D34965102482A8"
      "ED9E4E964D5683E5D45D0C8269";
  constexpr absl::string_view kHexAeadCiphertextWithoutPrefix =
      "72c12ce9b638c057b6b9c092c33cad9c8c5fac26cc64f96668725ffdada50dd1da9d1b65"
      "e9d1b2";
  constexpr absl::string_view kPlaintext = "Hello world";
  constexpr absl::string_view kAssociatedData = "associated data";

  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = test::HexDecodeOrDie(kHexPublicKey);
  util::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *key_parameters, public_key_bytes, 0x41424344, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_key_bytes = test::HexDecodeOrDie(kHexPrivateKey);
  util::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Create a KEM pair.
  util::StatusOr<std::unique_ptr<KemDecapsulate>> decapsulate =
      NewMlKemDecapsulateAes256Gcm(*private_key, CreateAes256GcmParameters());
  ASSERT_THAT(decapsulate, IsOk());

  std::string ciphertext_bytes =
      test::HexDecodeOrDie(kHexKemCiphertextWithTinkPrefix);
  util::StatusOr<KeysetHandle> keyset_handle =
      (*decapsulate)->Decapsulate(ciphertext_bytes);
  ASSERT_THAT(keyset_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> decaps_aead =
      keyset_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(decaps_aead, IsOk());

  std::string aead_ciphertext_bytes =
      test::HexDecodeOrDie(kHexAeadCiphertextWithoutPrefix);
  EXPECT_THAT((*decaps_aead)->Decrypt(aead_ciphertext_bytes, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
