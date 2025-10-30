// Copyright 2025 Google LLC
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

#include "tink/internal/mlkem_util.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::EqualsSecretData;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::ElementsAreArray;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;
using ::testing::ValuesIn;

MATCHER_P(MlKemKeyIs, expected_key, "") {
  return ExplainMatchResult(ElementsAreArray(expected_key.public_key),
                            arg.public_key, result_listener) &&
         ExplainMatchResult(EqualsSecretData(expected_key.private_key),
                            arg.private_key, result_listener);
}

using MlKemUtilTest = TestWithParam<MlKemKeySize>;

INSTANTIATE_TEST_SUITE_P(MlKemUtilTest, MlKemUtilTest,
                         Values(MlKemKeySize::ML_KEM768,
                                MlKemKeySize::ML_KEM1024));

TEST_P(MlKemUtilTest, NewMlKemKeyGeneratesNewKeyEveryTime) {
  absl::StatusOr<MlKemKey> keypair1 = NewMlKemKey(GetParam());
  ASSERT_THAT(keypair1, IsOk());
  absl::StatusOr<MlKemKey> keypair2 = NewMlKemKey(GetParam());
  ASSERT_THAT(keypair2, IsOk());

  EXPECT_THAT(*keypair1, Not(MlKemKeyIs(*keypair2)));
}

TEST_P(MlKemUtilTest, MlKemKeyFromRandomPrivateKey) {
  absl::StatusOr<MlKemKey> mlkem_key = NewMlKemKey(GetParam());
  ASSERT_THAT(mlkem_key, IsOk());
  absl::StatusOr<MlKemKey> roundtrip_key =
      MlKemKeyFromPrivateKey(mlkem_key->private_key, GetParam());
  ASSERT_THAT(roundtrip_key, IsOk());

  EXPECT_THAT(*mlkem_key, MlKemKeyIs(*roundtrip_key));
}

TEST_P(MlKemUtilTest, MlKemKeyFromPrivateKeyFailsWhenKeySizeInvalid) {
  EXPECT_THAT(
      MlKemKeyFromPrivateKey(
          util::SecretDataFromStringView("invalid private key"), GetParam()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

struct MlKemFunctionTestVector {
  MlKemKeySize key_size;
  std::string private_key;
  std::string expected_public_key;
};

// Returns MlKem test vectors taken from
// https://www.ietf.org/archive/id/draft-ietf-hpke-pq-01.html
std::vector<MlKemFunctionTestVector> GetMlKemFunctionTestVectors() {
  return {
      {
          MlKemKeySize::ML_KEM768,
          /*private_key=*/
          test::HexDecodeOrDie(
              "06f7d4f1495a828789f5543cb847369e10751ca5369a473c74e46043080f94f5"
              "25f2"
              "f8cb7d8cfbf3cf8496728611a6567afd446a6ed1d22f6d32f74ef266a97e"),
          /*expected_public_key=*/
          test::HexDecodeOrDie(
              "33e49cea9c631f102595637291548f7220782f498bca5073b8039759f5582f45"
              "aa59245f41e5516da2a779b325e039651c348f57502602a3b7b8482b4b1576c9"
              "3aa8b8c5155e5bc5dbc6a08d57103bc970b016ab7ab22320c430291ba1e80855"
              "64c4a13686aafefb510ce76e36876f2fdb1b7ba49550c15f5d366abe420e7ff2"
              "459cd7af36f5c285981adcf84020b04a66a0bc58172f8a34280fc32497a56308"
              "238a9f27ae95f0a593a70ae7594260e60930695f5f803eb2210fe3ac61c8bc20"
              "ec2566dafc399cea81a3834619420e5d85476cd573c7a08eaec4c60cf7999acc"
              "98724b934e259cda793dfda761cfa4289530b1f75b6a592730b8f5607eba701a"
              "150c38ac0e21038bfef496d2cb808f7342317789d1581b6f8565e3018d796013"
              "fed26b59fb226b5988633923a72a9acf42960c228f1e25b84f18ba4fd8762067"
              "9d6c7a9e5f4340dadc3af252afd28231e3d52cb924209e50ba1ca632de811ae1"
              "097cd89803884a8c750663baec78c90254f038574fdcb74c527610e21469398a"
              "20abcce9f50e1537867aa036bf1452cbf70850e8a5f5464eccc8a2af260a4550"
              "7e2da24c4868699065c95e3946ace90a655696f654892d8470a535cda5d58c44"
              "c8c0cb7bcc7104a847bc4cb1f03b8872143f5491c9e8c8ed46a6a6703c07d42a"
              "b8fabc4e25477245754d718ad8c88ce753c9756c2403948c06c1345c570fbd9a"
              "5932982f326a2f2ac69ebf5a58bc788fdb72a4d90865d3169d7752579cc49ad5"
              "e27479260dbba4800b521d21d22eb633168632b5209c4b81f32026a8111e07b1"
              "48babf740297af87239bc760b976862c551622416a6fb23825112308867ba70a"
              "75ba33179c2373b97492235a27c1f266cbc18f71c0596e47a285bc2e09397a63"
              "2309ff67739cb132d8c4007d2926fafc5eb56a6cf1960e87b4488c4895aacc6f"
              "cbbc4b6dd2b56cc69616653836550bbb9663b678370c3916fb832e17ba753d04"
              "787d78b0ddf11f6410bbe847cd6b1abdcee2835d50867a40137723433fdb6e94"
              "f902fda88b96d95af872000447c3649a93d3e0013dab5350dbb45c6190089c56"
              "cd4c1fce162daba74abfe8ae673105e0ebb94e52b37967b609741eb4608723e9"
              "858937b4996269033ca2cb503c4d3ccda0e15137cbc602728cc9bb5cca55b2cb"
              "c4579d02bdca430a052bbfc68bb5c8eb7c0139272c545d09f345b49a800314ca"
              "63c5097ef24cd793946410a931d5437becb557197affa37071954eee9c093a34"
              "86492362595761c83aac2ce46cdaebaa07ab3c3c1363c15bb8c4c869f54c6fdf"
              "a78924b954e0b480d3a128a2f64f7527beb2ec92ea6994dddc5eac10bde8a456"
              "09784e7948b6acc7c5da8526dd970870f46812bb0b53867668e17183fa638926"
              "1fa5da9a3ad8451094cd8ddb28683c1ce853c0e1cb3a4f79a168502242f66217"
              "2bc21609492fa57a9f077a1889c42cb2aa3bc2583275ce6b171c3e3aa4279483"
              "b204cb3a1a98535a2fe7c1b3d322c52dfb9e9ec46f926562ef1c8992a2bc5fc0"
              "47961898d1eb3d35cb1a018cb440d84de5047e50a4abd891c84f9431e36bb813"
              "4642e6fa144c15307a5122f07252b1e65b0e9ab3c2a184826c9a9cd938bdd588"
              "138a731c1b51787f166ca6205dadaaffc05c609f747b99fc3b918359e2ac28c"
              "8"),
      },
      {
          MlKemKeySize::ML_KEM1024,
          /*private_key=*/
          test::HexDecodeOrDie("870150f8c622ea6866db299c3348c737f0e8da17c1e7f72"
                               "1029b5e035db5942168522e0bea336dd93031199ab74b3a"
                               "cd684cbd03d6e56f304e5c28e7a9cba3bc"),
          /*expected_public_key=*/
          test::HexDecodeOrDie(
              "daa944e375a5c36c1f3771be499c297aba61d8762694256ef840460d10bed594"
              "641d58446e3795792c51f272383e78aa517112197230c3604993182d046679a8"
              "70495f1c44a6e2b30da7c251034f127561e02a234d0bbbb4ccc5a15224d06431"
              "08c44ad2973085371c80a064eaf524ebd90d5ad6057d45326a8b4ef532a7dfa9"
              "3ff83783ece423106c8b1ed2627b59ca34d71a3b4014698c9969db604589270b"
              "492124a80eba50909c2847a8bc9881b0788de95ad718a9c71a33b7ba98ab8ac3"
              "1ed744ffca6d6e08a170084c072bafaf7c25d5f56c519a6e3bdb30b0906192e2"
              "671da765ef53af8ac0197af2c9ac794a41038599766323718347f8821f3888ce"
              "250b84335eb8c43de4d9720f26b92531685af7576f62c6f39249c6645433387a"
              "8c617fdeb0650f77580de2af30019eb9959fb39ca2ed5364fc0a54e4809ac6a2"
              "424d284113e25179427b6a22936dc5839f3a9cb8bb49a5239ecd09278e432f65"
              "59bba0d56f9a9b87af068369c207b040022306a5fcc64d3264338a0789d7a833"
              "ad280b9ef2619c75769ed124a19c89a9b00a43c934b0042f24e28d2c353f2718"
              "ae9eb556bcd7c408f01e07bc7ad1d563b411133899312e5c6125f3cf39448ba6"
              "4c8a904414c32a8fc233649a2a69b98ab658094908f89c7089765e8211e5c75d"
              "949c6e53c6445d11902b25b452da79db853b78c8a629f1c5ef762f34f2126a20"
              "92c85b618c1a1bb506cd60e0c8b39b3c9aec088494c966878db1c3772b0992de"
              "4cb3a4958d2c43878f681a53cc207f446c6f95addb7047116bb4d5124b5fc532"
              "20401a7b5531fbb49bafa345479c620bfa8529f2a73f830c975b820b465a9745"
              "3483a746ec573289a8c02b53906c7423dac584495b6c771a60db498ae478a8f9"
              "a9833c81666a55a47a01adcd189b0e8c90aaa382a1d2301a873d9370c12ecc61"
              "04516e6b2957e3a7806c551d96aabe3b5cc47f918c467732dbe3a138305490c3"
              "8b33760d4b164bd509595415a3b560082a9b688b386c20f05c0667631555015e"
              "ba61e87174600c1fd0971b4e776e8452ad50748fd5a783ade73d80a97c8b07a3"
              "74ca53ba95c89157b5e2bb333518adce58c5ad90734ee20cc4646382f4bb91d9"
              "431968895f541a25da9a892c7086cb361e4240ae996afa5445c0cba188d13e4a"
              "8863c6918a7e247aa893c055a052bbaa3bd1b2731207006e5403e8742c844605"
              "d4aa64963b0af4978fbb7a1e409ca5470395dc24a700a850b189039f87bd2c78"
              "58f28a9e2c624ecea50f1f7889f6a99cfcfacb0c5861586c3e97a41d855319d5"
              "930e0aba9eb1b1bf013b32f6cb0d1570243eda540538a288d13bad128907d079"
              "25153925e9253c117e82ab0c27c49fc68162e465b0e3fb7c1671c0965c71b583"
              "6862301a85606122896e8d9a6d848c1818580ddc7955f3446f148338ca14149a"
              "205a3c6bb43e30abcf20a69f36a7a5e60efdf69b5922cd6a7744e420311f3b9c"
              "b2148ab6ea7e11b522c81ab0209a43f8da598f580fc8536b2838bb8ca0c26690"
              "5270609304ab78d6c40fa8a7015862b80ebc34a9ea25959a3c3fc4abd56a7961"
              "6215f2caaacb51033e02ba4b446c0fd47e515ca9ad44c7e3a2739b9b69242a6c"
              "c528880491c72c7858ac13804db088a97541ed11208b369bfab3c8e4890ff1c7"
              "3f2d783004c482458980eeb21f40c73d5d5282a78279d6f71bad650843c83d03"
              "23a7e90748b555853a50c091c31a9655b2388226e4524cdcbabb61543eb7caa8"
              "8396933e1a5986986e41da209f131a9bbc9a44d66ba077229c499386a4418b99"
              "0e20707c323846c861bcf227b2ff6ca3ee6511b37c190618c1e610be4672507f"
              "f7c7f5486930670d99bb6c2c28afaca54b815144aed10f82c27ad8922d5a9c86"
              "b15c9da866ad0ff96a2f569b42d52cdec8793d0414cfc35ddcebca8066b25e93"
              "0b36743db6b05a6ec6641b9403f88a5320842522f388683c72eb60bfe1db314a"
              "0b78a0a0cc76a692137c9613bb47c3f54911e67c1ba48a46081fcaf0974783ad"
              "ddc88492943d8b5934a41b46f95120fce5a21e0223dee7b140a924ce711e0e93"
              "c434616b58b02c2e30352599380ca04127f40a4134c5862c3bab08a3f265a467"
              "9c989cfc1f24c9c553cabb37ab2767f5ab2d7a20e57b0b65fb6e4a6119ba33a7"
              "36a9568de2ee95c312aad4c14639282831a3461d6e08800b592c8aa9d7ef602"
              "8"),
      }};
}

using MlKemFunctionTest = TestWithParam<MlKemFunctionTestVector>;

TEST_P(MlKemFunctionTest, ComputeMlKemPublicKey) {
  MlKemFunctionTestVector test_vector = GetParam();

  absl::StatusOr<MlKemKey> key = MlKemKeyFromPrivateKey(
      util::SecretDataFromStringView(test_vector.private_key),
      test_vector.key_size);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key).public_key,
              ElementsAreArray(test_vector.expected_public_key));
}

INSTANTIATE_TEST_SUITE_P(MlKemFunctionTests, MlKemFunctionTest,
                         ValuesIn(GetMlKemFunctionTestVectors()));

TEST(MlKemUtilInvalidKeyTest, NewMlKemKeyInvalidKeySizeFails) {
  EXPECT_THAT(NewMlKemKey(MlKemKeySize::ML_KEM_UNKNOWN_SIZE).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid MlKemKeySize")));
}

TEST(MlKemUtilInvalidKeyTest, MlKemKeyFromPrivateKeyInvalidKeySizeFails) {
  EXPECT_THAT(MlKemKeyFromPrivateKey(
                  util::SecretDataFromStringView(std::string(64, 'x')),
                  MlKemKeySize::ML_KEM_UNKNOWN_SIZE)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid MlKemKeySize")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
