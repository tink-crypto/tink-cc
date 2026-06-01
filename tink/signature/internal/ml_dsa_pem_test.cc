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

#include "tink/signature/internal/ml_dsa_pem.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;

// Test constants copied from signature_pem_keyset_reader_test.cc

constexpr absl::string_view kMlDsa44PublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kMlDsa44ExpectedBytesHex =
    "d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42"
    "f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c3"
    "97d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00"
    "138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72"
    "e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a7"
    "8cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5"
    "090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f6"
    "2eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e"
    "826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f518"
    "7df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca0"
    "6048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4"
    "285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7"
    "524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90"
    "784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bd"
    "c79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6"
    "559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad4"
    "5f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e"
    "90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f23783"
    "12b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4"
    "f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784"
    "b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b0898"
    "44900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb3"
    "9e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82d"
    "cd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670"
    "f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8"
    "b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec025"
    "1f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791"
    "f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df5"
    "1522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630"
    "083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083"
    "be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0"
    "b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fd"
    "aae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cf"
    "d6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7"
    "d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc0"
    "70b55869e4db9784cf05c830b3242c8312";

constexpr absl::string_view kMlDsa65PublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "HgLy6ERP\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kMlDsa65ExpectedBytesHex =
    "48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2"
    "edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212ca"
    "c7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf55"
    "39a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff"
    "3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67"
    "745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb0"
    "03b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55d"
    "f69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d857"
    "1610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399"
    "d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882"
    "f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d9"
    "8deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6e"
    "d175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3"
    "ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc028366"
    "6b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28"
    "ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b"
    "2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa67988"
    "2a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96"
    "af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2"
    "b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3f"
    "db67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d94223652"
    "6e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2"
    "f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5"
    "412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f"
    "398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d9617267298"
    "0cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798"
    "bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753"
    "389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2"
    "a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38c"
    "c93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f192"
    "94e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6"
    "dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0"
    "de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e"
    "2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf"
    "1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca"
    "3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d62"
    "7c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed400"
    "80d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f4770"
    "3a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b"
    "4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686"
    "b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7"
    "530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35"
    "e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6"
    "c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a318"
    "1954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69"
    "a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a713"
    "1c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef736719"
    "6b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d"
    "6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f"
    "03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e"
    "20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a0"
    "6b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13"
    "fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f";

constexpr absl::string_view kMlDsa87PublicKeyPem =
    "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kMlDsa87ExpectedBytesHex =
    "9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9b"
    "a21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d"
    "5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe190706"
    "79af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c795"
    "59f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1"
    "c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85"
    "f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23"
    "c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b44"
    "0d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f968"
    "77d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa"
    "1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd31"
    "67f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e"
    "116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b04"
    "39eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3"
    "c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50"
    "c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571"
    "cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb"
    "4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a"
    "72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc"
    "3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea"
    "8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ece"
    "c32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52"
    "104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722"
    "788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6a"
    "e82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf7275"
    "4e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6"
    "650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee1"
    "04511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b8"
    "5c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b4408"
    "4e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1"
    "a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bd"
    "b6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e91470"
    "54ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd0"
    "28b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0"
    "de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec5220"
    "47193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea"
    "2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d547"
    "16b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c8"
    "8f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c8105"
    "4994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16"
    "bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29"
    "ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414"
    "ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc"
    "732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434"
    "d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472"
    "e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b"
    "2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a"
    "42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f"
    "0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e"
    "8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7"
    "b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e"
    "939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa"
    "4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aad"
    "ae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c"
    "3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7ac"
    "ffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f"
    "461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965be"
    "f1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e14"
    "9d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6"
    "373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544"
    "c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f6958"
    "7695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697"
    "f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d180"
    "2762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c"
    "5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c"
    "35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1"
    "cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c9366"
    "1e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca"
    "28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947"
    "c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a3"
    "4a60";

#ifdef OPENSSL_IS_BORINGSSL
TEST(MlDsaPemTest, ParseMldsa44PublicKeySucceeds) {
  absl::StatusOr<std::string> raw_key =
      ParseMldsa44PublicKey(kMlDsa44PublicKeyPem);
  ASSERT_THAT(raw_key, IsOk());
  EXPECT_EQ(*raw_key, test::HexDecodeOrDie(kMlDsa44ExpectedBytesHex));
}

TEST(MlDsaPemTest, ParseMldsa65PublicKeySucceeds) {
  absl::StatusOr<std::string> raw_key =
      ParseMldsa65PublicKey(kMlDsa65PublicKeyPem);
  ASSERT_THAT(raw_key, IsOk());
  EXPECT_EQ(*raw_key, test::HexDecodeOrDie(kMlDsa65ExpectedBytesHex));
}

TEST(MlDsaPemTest, ParseMldsa87PublicKeySucceeds) {
  absl::StatusOr<std::string> raw_key =
      ParseMldsa87PublicKey(kMlDsa87PublicKeyPem);
  ASSERT_THAT(raw_key, IsOk());
  EXPECT_EQ(*raw_key, test::HexDecodeOrDie(kMlDsa87ExpectedBytesHex));
}

TEST(MlDsaPemTest, ParseMldsa44PublicKeyWrongPrefixFails) {
  EXPECT_THAT(ParseMldsa44PublicKey(kMlDsa65PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlDsaPemTest, ParseMldsa65PublicKeyWrongPrefixFails) {
  EXPECT_THAT(ParseMldsa65PublicKey(kMlDsa87PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlDsaPemTest, ParseMldsa87PublicKeyWrongPrefixFails) {
  EXPECT_THAT(ParseMldsa87PublicKey(kMlDsa65PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlDsaPemTest, ParseMldsaPublicKeyNotPublicKeyFails) {
  constexpr absl::string_view kPrivatePem =
      "-----BEGIN PRIVATE KEY-----\nMCw=\n-----END PRIVATE KEY-----\n";
  EXPECT_THAT(ParseMldsa44PublicKey(kPrivatePem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ParseMldsa65PublicKey(kPrivatePem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(ParseMldsa87PublicKey(kPrivatePem).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}
#else   // !OPENSSL_IS_BORINGSSL
TEST(MlDsaPemTest, ParseMldsa44PublicKeyUnimplemented) {
  EXPECT_THAT(ParseMldsa44PublicKey(kMlDsa44PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}
TEST(MlDsaPemTest, ParseMldsa65PublicKeyUnimplemented) {
  EXPECT_THAT(ParseMldsa65PublicKey(kMlDsa65PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}
TEST(MlDsaPemTest, ParseMldsa87PublicKeyUnimplemented) {
  EXPECT_THAT(ParseMldsa87PublicKey(kMlDsa87PublicKeyPem).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}
#endif  // OPENSSL_IS_BORINGSSL

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
