// Copyright 2026 Google LLC
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

#include "tink/signature/internal/ml_dsa_prehash_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/ml_dsa_key_creator.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  MlDsaParameters::Instance instance;
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string expected_prehash_prefix;
};

using MlDsaPrehashBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrehashBoringSslTestSuite, MlDsaPrehashBoringSslTest,
    Values(TestCase{MlDsaParameters::Instance::kMlDsa44,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030405, std::string("\xff\x02\x03\x04\x05", 5)}));

TEST_P(MlDsaPrehashBoringSslTest, PrehashOutputLengthAndPrefixAreCorrect) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  std::string message = "message to be prehashed";
  absl::StatusOr<std::string> prehash = (*prehasher)->Compute(message);
  ASSERT_THAT(prehash, IsOk());

  EXPECT_EQ((*prehash).size(),
            test_case.expected_prehash_prefix.size() + MLDSA_MU_BYTES);
  EXPECT_EQ(test_case.expected_prehash_prefix,
            (*prehash).substr(0, test_case.expected_prehash_prefix.size()));
}

TEST_P(MlDsaPrehashBoringSslTest, PrehashIsDeterministic) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher1 =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher1, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher2 =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher2, IsOk());

  std::string message = "message to be prehashed";
  absl::StatusOr<std::string> prehash1 = (*prehasher1)->Compute(message);
  ASSERT_THAT(prehash1, IsOk());

  absl::StatusOr<std::string> prehash2 = (*prehasher2)->Compute(message);
  ASSERT_THAT(prehash2, IsOk());

  EXPECT_EQ(*prehash1, *prehash2);
}

TEST_P(MlDsaPrehashBoringSslTest, DifferentMessagesProduceDifferentPrehashes) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::string> prehash1 = (*prehasher)->Compute("message1");
  ASSERT_THAT(prehash1, IsOk());

  absl::StatusOr<std::string> prehash2 = (*prehasher)->Compute("message2");
  ASSERT_THAT(prehash2, IsOk());

  EXPECT_NE(*prehash1, *prehash2);
}

TEST(MlDsaPrehashBoringSslNonParamTest, AcceptsVariants) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  // Test kTink is accepted
  auto tink_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());
  auto tink_key = CreateMlDsaKey(*tink_params, 0x01020304);
  ASSERT_THAT(tink_key, IsOk());
  EXPECT_THAT(NewMlDsaPrehashBoringSsl((*tink_key)->GetPublicKey()).status(),
              IsOk());

  // Test kNoPrefix is accepted
  auto noprefix_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(noprefix_params, IsOk());
  auto noprefix_key = CreateMlDsaKey(*noprefix_params, std::nullopt);
  ASSERT_THAT(noprefix_key, IsOk());
  EXPECT_THAT(
      NewMlDsaPrehashBoringSsl((*noprefix_key)->GetPublicKey()).status(),
      IsOk());
}

// Test values from
// third_party/openssl/boringssl/src/third_party/wycheproof_testvectors/mldsa_{44,65,87}_sign_noseed_test.json.
struct MuTestVector {
  MlDsaParameters::Instance instance;
  absl::string_view public_key_hex;
  absl::string_view msg_hex;
  absl::string_view expected_mu_hex;
};

using MlDsaPrehashTest = TestWithParam<MuTestVector>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrehashTestSuite, MlDsaPrehashTest,
    Values(
        MuTestVector{
            MlDsaParameters::Instance::kMlDsa44,
            "db9ac67708f2ba0fac1f92bd802f9be89ecab966feef59872a1a9ac90b1111170a"
            "561290ae86b13968f2506023c014ba09fa449a26e4e9d35595e73986506cc8790e"
            "4d07a94d6c736f7ae78cc5e3e3cf025ce06a09252bef97fe92e94cbd107b1844d1"
            "a7c690d88bff9e9336f8f58e0bd5ee384de9c7ffbb149a6fcd87c77288601d8843"
            "e28e0c7a60149d02ebc57b183c39888d98b61cd8ad48135ddb8a1666743bb689f4"
            "4c1a92d52017b6a8fa493eeb839dffb086a9a6c399b194a52f0e4164c96ff8a2a5"
            "4337de24350a866b5fe4195257778e72511221778f1eae5fa93ed3532f696b9b07"
            "67aded85f62ea311027c7f5fc4182dcd2864b1c26bd6dcf72ebdedf70471327be0"
            "ea1c2ae53e46489c6dbefa512a78fdd7be0ad3ada16a7f7b1ece49817b44868a2c"
            "c234bfdba556c32cc92ec2c5e8a5d206f2e4ee372d41681e67d1b7e7b0061870c5"
            "7f600fafca85f98aed8ce4ba76bba961f9ed56e563220d3ced853b6b28e7527da0"
            "e0912bc932a23c8bab811429bbb4d49b2770bcda44abb932b11c0a5866409fce39"
            "fed2b459c86c8f6e1ab0aefc5879503f4b21a49b4b2de6760c9b6aaf041144a656"
            "a26af39f4578e1d482ddc1360ef751d9784b860ec373d415360fe99f32e126a2ac"
            "1243430e8bed1bc90b19b3d219c2712edcf81c44b4331f6421088e662b695e1fd8"
            "fa5091f616ab60af70f159b63368f1ac60d77b279ed47ef7f24ec2044bb6c2bc76"
            "d933ecd568f7e663392afc1d335abac6c03670adf87747dde90052f5cd45f7d30f"
            "43a4dc3c500ceb658fce235c171240baca1b5a14733d774b9416c540f53eb83481"
            "afc98344b12a4309e6222b08d978430467497010314c6f6b8caf65361c21610639"
            "5275a67d7500dbc120f7918c6f8db7aa63fa965b4a22c70dc88f727d768ce2bfc7"
            "597fd470184e1c59a6b2e1204cc8c3d052c594d5771e0ccc8cfb191f47038b1c06"
            "72f07caf4747562d3d76a9816fb1def1391cf0f05fcdbf2a0eb6c21ac24b26e74e"
            "e403133e80a79313ddb02c1fa386c6dd1d420195343e3a104aff6d60887f7304fa"
            "9e3bb59bb55f820dd85b1445c54e9a38dc1c7f3b88eb36a9f48d13455e51c93482"
            "5ff3cd8bedb2b5422344120399eef83a360b83440ebdd8ea6e01c95159e3735bb4"
            "408500caa785ca4049891c7331c4ea31ad9060ece768fd339e6904f88e27bad3b2"
            "8845687be2cc9314f300fda56fe3ff2508e54c59123b068f86fe00213d5af8da1b"
            "1735423ed688f097c306dbc121b81f532fcaf872d9f80596642295d6e4bead4786"
            "44081618ab903b39e9b5e7cc0b5f2742d8337b18d4ad4788db7443e946cafc1762"
            "a5da84070e8c2fd86d6c633f0b44ee234ba11b9e1440c94a08d043701527969040"
            "5353059020fd2f58f15dab18754177244adfb81ceab79c7840bf3884a3d364afc8"
            "c453a425fd8c5378eaa7445f8c6256bfbd03a66c53e8cf27e2c52f14ef3294afe7"
            "9cda408f5dff933ca0211a78a4e3be3d9a932558ed71ed19bbb57f87937fa3d4a7"
            "8128491ff096a261045bdd186325c42caa8c7564195a4d2499a1c17d21a52d1aac"
            "d221d9c8a1866963a20390f2fd43dcf56b308a1c01c38091fd3e04c12b695de497"
            "d48bcc268d50cb0bed793b8e6937e8d533afd568521f1c9377a3804d38e785674d"
            "7ce868d289938e33dda6edc76d25b15fcb38852b7803cfe62f08d9fbd070957c4e"
            "6f134973964c9dc009985c8501e7d8f72e7ec285d5289fdd07f64d62acaa9737b0"
            "39efa7a9d1d175577c6bcf9dddcf692877af38e75263bebe2453155be61f0723c2"
            "74388a532abe29dd7023e327085f4c9dda41839b7b3357ab9d",
            "48656c6c6f20776f726c64",
            "0ba2d90bc4fa5877844e47f7563eefccf658f898eaf4197b2a9a89d3df683955c7"
            "3a80895ac0a51cc9049d44cdc1d1c550ef3870c1126afdb3d52ee057cbbcdd"},
        MuTestVector{
            MlDsaParameters::Instance::kMlDsa65,
            "f5408337d0fee65c28851226a5fa81b58464632c78e2a9bef70d330f2e3a5f74d9"
            "cf676aedd1067c91a5dd5d4edc46f868a93ffec9f44e254e44f682a153aeadf228"
            "e8db7c5fcfed30cc3408e261ab896876bee56660d2a7c1d7eac20c5754255206a1"
            "78f7156295065ce7876f90c48f44bc37f3a00e32eefd3a4bb1e298fe283d106eae"
            "f92a33a594253a2a0790976a1d04636f8672d28c06c852ea8bb43b84bff512996e"
            "7616963d5b9a2906466a152c7ea9be178be35405683b44367af85d2daad87630c1"
            "e21ba5490154f0141780f5ed0407cb0b975dd56d5930f9b26413b843b83f369330"
            "4b0038bd3e4bb398868060ea18c9c67099376470a50deb052e4056743fbcdf0341"
            "b192663bd1c21ba3b3d5666e0d0e29c4e1ed0759ab0bd9d1d355011b94e0ff0c04"
            "9b03ddb7138640667144fcacd7265f55a07e5387f1abd30c037cf14d436aa855f8"
            "27049215440d8007f61460500d943f57ffb6bfee6fedd2fcec52882d7d8da1aab2"
            "9e892c8beac3df3234b4a7d2eca3a45c6623c52bbdd07c1c94314b706988a52029"
            "f8f8b06e874b741d72926652c78c6ace2cfd8864eadb2e4b39cafe6e03e4edbafa"
            "2747db9bc42f92af8b031e3e380846b1bfd15ade88c285d6a6fffe91eafc8b17de"
            "6cbc68575f323cc09fc20e49e8efd76f9568bec486b78df4245428d8d0d5f53873"
            "e11de65fda4c770b521a8c67f5c51d48cc26358954514447881fd9a42e5891dac7"
            "e1db5249d7861b322111e5fb929bee9ff5e9d5a2667ba93e63fc03040d2e82648f"
            "89e89dec1d1d2dfb9efeceb7940f7dcbebeb5a239cc1c54d8f7d52cba220d0634e"
            "15df46a58280bc5a48840bd39274cfde150f9ad9a40f6398d715350925f0e05019"
            "44409f32331a362bdaaafb3d8ce71c964332d6afb7e684f99951246d88081c8674"
            "4ae68133f22c53a4b5ae258f230a98491d2d43a79a6d0f4d54a3b62013965ac7c8"
            "2d0507125a38a0277f81cbc1d46cef2a131c6f51b88ec0baae0c82a6a0e72831cb"
            "06f9116cff5111d597e01057d32805a008f52c9aec3311139bfb35982789ff83bd"
            "d0c31e9f1080e8ed8eb99fde66bafb29e3357389fe3785b60c78e229ef073e1b65"
            "e34d848bd4d8a4f251551e2d38d2546afbc205d3c6dab34d2b962b1afb44f1d22f"
            "c10c6744fcd6b636afd3cb414b16c2e0d708fe9f51ff19120bde693b028b6d1e6d"
            "be37b4b8b3bc7c6f7a842701603869d3ded572500f085502efc8d3cc62b30e5cdb"
            "cb5e86d9c0d42973bf755df539cc0aea58f9148386db67bd2bf70cd12ccd96d5c6"
            "6fb271416b772465228dc44b079178f9b766370b66a79b871faca246ca6f8f63be"
            "9f0668297ac446cad5cf4a83318b1b00ecbd283f0eecee60a9a37a27abdbdbe382"
            "e307970002837dfc0bd3934ebd008918fd4bd383c02c9d37f694996e989a490757"
            "67ebc4a2981ef5275455e026cb0bd70946cdd1fadaf251381d324f9efbb860d1b2"
            "80c29685bab97d010676273b45cca12ac3966aae342c84e2357eccf252577743b8"
            "787967b40b07ef2d3d9e6c1a3bcb059cba0fdb7f0d4f815c242b8e14acd3375e60"
            "8e9230ba3cf8718f43882a3e1e661a2bbe81830d34741f33473e263b3790abe67a"
            "cf29f5df44865b2ffbc96975fd62738a64112deda5a2534fb0a23b3b3024df9863"
            "91badf9041c593c313a7ca1e1fcffcb65b07b9a99337b4a4acf616cbe1553eb954"
            "1f38aa6247342905995233a28172ca13396b2a9662970120f82b92a213f43de7a2"
            "32ccca3268265c9ce042d50915430a6c455f32277da42f9962fb9163b623231ebc"
            "080fa7b8e9f9021fcf85b98f9c483e4d2226b9326a5bcb2e7449ef029ae142d3a0"
            "f0c28bd4f7e9c51a12e1336f24dfacbc3f808a8f7dd683027bc948763b808fb003"
            "7394b8b41bc9b2ec7887e67584e03d11b15ca203b2bcb43f8881638c4e4eee7f84"
            "6d09c7f89b7739df22b2c3acc235032ba8f7ae27b5b9d25733143e80a4cdde6770"
            "719c1e66ec2ce683612233e88fafff84c0745a98aa1254c8219c6c556348c2b5d1"
            "beeb61532d6bf7bde153271dc647460beb65fe0055b33fd6480dcbb9d7d471952c"
            "fa5be260c39721a8c5c89b9e966ae2dc9036451ec9f2c49433b2225e13f23e20c2"
            "bfba81a7b3a555883449238f7d48213e9f10ce19e76f1bdcfc73ee5524bd7d8be0"
            "a4b46784e238233c04fb99383ec7726f9717e1179dd14fba9ad6c2ebd1699f0ab0"
            "e57e6cad23875b029e89cfda06f51266ecd2eed4edafb51e82f2a506d57ba74da6"
            "11774ca5fa2fff4a976519de425885e7d09219cf815b1767d4fc5a72c18918991a"
            "285086a6a766614a4d245387da50f28dd778fb33ab88c0918feba3768c55bb1f07"
            "aec33cfeed33d6faa4d34fd7227b365533c1e67dbc89f0b20195cf1cbd480d333a"
            "de1c9bb28308085b72ced430268c1492a27050c43668adc9cf8b8509447cfcd3c8"
            "f8d8eb554f704101786aa9ebca86991d250776a37a1f56fbf7d08e591f978da49c"
            "3870625879f70e2418aec5cba32fa8c346fa9038baebc35ad0068a4d03537aee14"
            "c2e71570a87490377fa8dd66f995aa044a522f0c7025a7ab2dd5ad30a64268dc11"
            "2b7f9fa156df64d631f55f1d6edc55cec570a9c7372e29e02c8d4867bae249431d"
            "cf6ed2794a0183f0f7501201feca4a81d334c642fc8d38e9a90fa77429665e09e2"
            "14797dfa455ff47c4f219d3a2cb0176bc2236455123c1c5da714ad29d580fb194f"
            "87173a18dc",
            "48656c6c6f20776f726c64",
            "de30bd32395e1998bcdae79ad419cec6ea9e9a903fdc552c6e9801208174d80a9d"
            "2f3902a144e62f89d6e505cc9c69fb01de013fc1d0204ee4dcf5fcc25f1378"},
        MuTestVector{
            MlDsaParameters::Instance::kMlDsa87,
            "17a508179b35057099111733da28fd1a2265de7d8ab22d5279f13bca84cc42a5b8"
            "c9644c121e7e1b81723c5295be288fb6c36bfa188b6e08d913a152350947fa2c8c"
            "cc3fd01b319f65a2058a1dff54133946cfeb408d0b6dfde6bbebd7e0591cfe83b8"
            "b5452ceef6c855f7d33e06a0d269345089ed0d3ad67d84d8a4a34d16836004cff1"
            "25469e8c3387abd788b620e30c1fc23909117a0e34c42a6631d9791347b1b2a3c9"
            "ab3082416211afb7bc3f6ce630a7019af19f736cdfacb1e7db66b65ef56844d2a2"
            "b0753d09283a7a0b66f77596384e95f7ceddd1c4ba20edc11f1eaab695bb963f6e"
            "da1c383754aa372a0d7729bfa6e0f142131c2367ba3f89ce3de6c357f9a7225b7c"
            "b85f6b3e8a3a122e8501fd1446b8152a415c19dda1d2e4590cd994f6664b4d1abd"
            "7381468c3a085abe2741a0cfbb81880664b271677245c4a471bf8bb8e0192eb32e"
            "4fb5e8560f3c50d6b19a353e486d0fcc2a35ac046286e707e095f61786d9221268"
            "6a65d39b6863e0f8cec1e1997f2f845e4878ca9df650c746765296790863e51d01"
            "2d32dffcbd746aa2276d04c0a57cd1b3d6ed06c0d66a0897aae5c49c97b6f19ae8"
            "29baaafbfed28a52c05963c6eea9eff69528294207f8cda75280f7c486e6848791"
            "c8e37015479f2e13c28a9fe654dbde11689875203aaec51be3da7cab1cf31e4ec4"
            "76c0c830cbdd04ac02167c0a6fbfdd6548b1fa525d235c7e3fca8d63e6427503b0"
            "a45c0bfddb428b837c32e8755441077bfe1c0142bac357b012a46545bf4148d465"
            "472dcf89c9d73b62357087e229f53a450d3cce41c8ee21a9d54b61e34a794f5b14"
            "06a70724ab0c3712c49df231ef30a956075e907c51b63dd1f9453dbe60e25b0f3c"
            "c0354dfd7c9119313919e77cb2c92f544d3e5302b8827603e936b567e99bfe9904"
            "932585a9f01a5a1b5bce07565f1d84c6b1c5c86259e1fefcff18cd06861122be68"
            "36be21e40be4eaf6bcabee8f634f95520aa914bb51c54dbd67d1b9dc5e38831e78"
            "6c283979a963a3206b98e339edec4128b0502d4d47813869713e431a529a03c7f5"
            "4b50123680f2b7f256f5d2b40642203259b9e85c62253d5670ce372193f28b5aa4"
            "8ddd643c54756a2cff808c109f74772961d8db6bb8a17547c8f29c7f5ff3ea0674"
            "0b867d84917e07f3978ad0281a20689eef58467e768b6178a9b36a567289fd3976"
            "2bb3e4254031b2798a4550857f6af369d484392cddd7b48eaa2942e2cbfe754d5e"
            "e2da2b7fa71222e4a525ff5224d551a778ebd828e4e0499adc74ff0d59a5abc78a"
            "d6a8abafeedb3c99045a14423507f85597b1a7f540982f7d72ea13449110b442d5"
            "4b78029b4c7fe3b49396dc6c3b7d58792538fa907963de10a4b724548142541cdf"
            "1512e0f7ff1b10a93de63541b8cc3268b4de20ed26739ee8973b6507ebe4896560"
            "2c35fa3f7d4278146b598d7d7044e16e97e9351f7c51ac25573b7232ae2432638e"
            "9166190e7f7a7dcb5096ecb5d10017cdea2a82b4f56c7385041c6919a7e36e11be"
            "ac77ec3f25df44e7b596c1542c1e376de3667c0e903fe25b57c338e9d93c5570c4"
            "84f0ddab4f57d38f292b23599d9efc7a9fd9e078aaddca0acb1a196d6c45d3c8be"
            "6f39e8cdbe3299e370b262e0bf6fb5f005cae2b12879289d00bd8039de6a571c31"
            "0d87557f5c9a4f64a0bde7177a8464722a04bf87fa2cb0e312d4fa6e536c61d65d"
            "c2c1baf144b0d1d1d75f4c860626ff773933efa9941d105c53a1d92c4f7c7bba4a"
            "a969590acef1e50901870f59715ac14d9846d83871a77367be57c63f88bc2c02ea"
            "bafe678f44925a3e605979282fcd3f284736a1d346c033cb782dd615e886683fc3"
            "7cd87a91422857774c63c6659096eba393c56225ed8c3485b4f89ecb07d5352628"
            "1a6426ae7d67cda52fec5ac32320caae9b96000bcbe9e8782be88cb1ca6dcaffb7"
            "4ef04c77e03a994bea2c89e4fcfa44cd0c9f4e30705a8b7b20df8c76b05a447940"
            "0e07db03d243e9fe4c90d34e9245f1e574be9a388f5355482077e4e98b919de024"
            "e666fdd7d51ed2a0d58a823e7497eb07303cf1d6d5f10a536be980220de5856727"
            "e5c13981839cfa19740988e7771a2b984f53ae3a5916ed881a4a90fe524f0bb377"
            "8355882864f8961fade32e656fcf9f524e748c8196a1f1bbc57bf8da7b36de9b00"
            "80f0c7bb8487a2b7bb7a81a8ff43a2539b367c9a48c70041520f05ca3dae316dbb"
            "e3118218216f52b7bcdba7557c4c9d861803a5e2ee01d3682e1261d7cae0a99fb8"
            "de909eb2bc1e112aa43cc2fa9c76a222bd85faaaba5d9ec2198ac45a295181a324"
            "a0592632b89e2752582cd5e01e1a610e7563faee10b76d853109e257e7c0c248a9"
            "fb7933f514b07b4f4e3a4a3d2cd22e8cc45ebda3bef5948aa050f01eff85ae98d1"
            "9f69c51e67ff89f2df0c5268acfdd325e84591317e05cab4f9e6358f249c4ddf40"
            "19fbc8f511549a733898a50efa9e0793083de0b15b5bf78d9f63d8df830d42df2f"
            "efa27b89e0ede2a702eb9467118fc0ed44edc63ad1b1935877c34843fea06fdf38"
            "8bbf83e501723a13cc6cc2efbb9691fe28fc1d45270591e5bdf7aa1c82673544ee"
            "29d9e6c9da3328f21e9729bffd7f4e56de585909679a74037105fdac3f51ae35f6"
            "9d9763d2e4cfeb1d4a8fdce99bf1aa21f866a9f523b2a9549e12258a4d19900cf5"
            "db37b67da19b23563bd1d701c6106fccb28e4689c62e1a6cf1abd763d7239c2258"
            "b765610d4478be9f1650cb8d18923592ad0024076e52f9bd0a3894fe97bc0a1646"
            "b4c37f62c27f32d0df270260f47c49a5caf110e4cf80168a7d54b1c70bed9bd5d9"
            "a143ce869a05cd44ee266aecd6bfedb39be79e7c7d5c11a99575ebc0f389cc55a4"
            "fe1469a2d61b70bfe4b74e3e27521a037d2b9f4fdb377231e2ceb214ba90f69538"
            "65c683215203ce963875c6524c01b789e0389a9f0c386eb236f0dfba6c95df4f28"
            "ccc7ae7cd473f9dcd20817cccdd211bcbc78b064e936e4ba2813df531128428ddf"
            "410e6ca07044aeb4cfcc0a16c995ec51c8af16a541ce18dbeb69a26635632dcc24"
            "ee52a5eedce38c502cd0e356ec31341c893f92e6063c3a160a53d34b85e92357a8"
            "ebaaad8f206771be43ee48cc409825a7094bda529ee18776d9e67f1fa1c1419514"
            "309d70ba2443be2f63b6943478d6c0f56dd058731e53de4c30bfc7d915e9284a56"
            "248e81944392881666680d4991f04269ec9a83b24b458ed59a6c274de452ab3013"
            "c103a4920543e6a7d22dadfd764f6ea39d49b910ee0dc216e547aa5fb4382a72a5"
            "68ebe83ec00416fb5830dc21c24ae72416602870cb52c3a8a1c4c12a4b287b9b80"
            "0d31c287ca161f404a9e598a5358d28b3aae43e534846bcd0d7a9c7652ae01e669"
            "8c79e315aca8198f36de45af7084b1cb21ca2ba0ee3a547a7343a10ef9e3fd17b0"
            "a4060badd1409a0562cba25b84fd578268fac53cfbca08e6cf6e5419f57262eb58"
            "13c1d1324e0df1d483ade08d8f6c62498e262485ac7c2872b11b42e5c1b797fc12"
            "e838b38a711d364d45cd1ed35f7faffdf4b0fb0eaa312fc3d5af77909b0649cbba"
            "cea10c9831273922b5b05172face9ce6cf324edf6e2f5f5fa0a9f0463eee938b30"
            "adf3e55664f94d274cd87dea901a7e08e805",
            "48656c6c6f20776f726c64",
            "00d86c57be5399a1841b734bbdc6ad234218ec65376768f844bec76cd3585696d6"
            "e648ec8a069bd929f2be80051679f2b8bec414f715261148f42eddaf3a9b43"}));

TEST_P(MlDsaPrehashTest, PrehashMatchesExpected) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  MuTestVector test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kNoPrefixWithPrehashId);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = test::HexDecodeOrDie(test_case.public_key_hex);
  constexpr uint32_t kKeyId = 0x01020304;
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *key_parameters, public_key_bytes, kKeyId, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl(*public_key);
  ASSERT_THAT(prehasher, IsOk());

  std::string msg = test::HexDecodeOrDie(test_case.msg_hex);
  std::string expected_mu = test::HexDecodeOrDie(test_case.expected_mu_hex);

  absl::StatusOr<std::string> prehash = (*prehasher)->Compute(msg);
  ASSERT_THAT(prehash, IsOk());

  std::string expected_prefix("\xff\x01\x02\x03\x04", 5);
  EXPECT_EQ((*prehash).size(), 5 + MLDSA_MU_BYTES);
  EXPECT_EQ((*prehash).substr(0, 5), expected_prefix);
  EXPECT_EQ((*prehash).substr(5), expected_mu);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
