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

#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/bn.h"
#include "openssl/mldsa.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_private_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_test.json.
constexpr std::string_view kHex3072BitRsaN =
    "00dc8f7880672f0cf9d63617a8a58bdd271a109badda0fa826f94b8a795526b6a49a80564c"
    "caba8a9491a935a53edeae1d9a7b5463d9e2ef3ee0ce7bff5d4b6c8147b5c073c2f220515d"
    "531d55a36687a6de3c34775c2f15191ac0a742d7342228c8d910fe6bbca439539c485debcb"
    "d0ee0e4bae317503b83cee8100ac7bb4587467cbc4373c4bda2eedf7c41631e50922b580f5"
    "bce81d24b208cabcd2d75fcfe99f75b493dffc5c9bd990f7fc3bf2efe392fecae36f3e4ef4"
    "456c1b5de99cc7451733a910b6834b61ec29274d986be3752c350b13a327dabc08dfcf6565"
    "499ad26e853446633eadb2970ca95bcf6bf05ffdbc2a804378d76985a71f06f90979f9fef7"
    "16c36aa625a45b5eedf50825a53e9d9435b23caab9e5c64d38fd3a767e185ad7727d6e15f9"
    "e9bab2f4184d6487695db9a2698c672b2e823410dbef1d93fe40c9d357ee9fc77f849de113"
    "63f583af8ccf5181ca1aeb944c422516cb401e950923e4bd881439fa1093c77582bfe1ac59"
    "93674700b6434339e0245315d86fcb";
constexpr std::string_view kHex3072BitRsaD =
    "0501205bd17b88d0d6626dd0fec898a0fd7f68f8dddcc314f74d167c40495b958a87e4ed63"
    "202e6ac68f4f4f4b88e3ec7a07d85757a7458468b766aad9a40f77337855408b28d140e75c"
    "2e6b3604ea8907bbd7f8e9578c2400ae645d28e2deef8bf718e29cf12fccb92fef9869f43a"
    "ee5bd6adc223848d169cd6c27c2766652766ff81993b3e015a553decee0ffdc1624f39f8d9"
    "6b6ed5d95047c1570b59fa2eb3d688dd5e14acc9407b8094f18b4694244eb1adcd655d873f"
    "57ff9af6e4fec470be236baf3b20c2040ab360d759c8b4e618bf8bd4e0ec6698f1b72c7160"
    "ed0521c82b5176b60fb63503d0ae23f6e2fb7a609305b0af62150b921ac53f4de899666cb0"
    "1db0c9d8b650753015c1b6e682e6bf38204e59f7409c3808c0e53f254935540a381a963c2c"
    "1a77c6f987f06a07a0572686ed22882dbc82e7823cec080a58d72b09d00cc1d245cf158ff4"
    "9cc40599d3af719dc301b4aa7f5b03629ae853e9daabe284db86d5c41d0401143df2b4593e"
    "f4e3747209c523f5a7f80f02d011";
constexpr std::string_view kHex3072BitRsaP =
    "fec6a10bfc49b58a2c850eafebdb997649a95575a0c17631b011cb20d7a320232a815b9af6"
    "040d7bf23d267e5e06304c33e04c85e6d481442f010a9758ba08364a70035ef99e9c98eeb4"
    "31505b2afb6779d1c91d0ea2fb0a65dc391e79ecda7d52fd7dd69923b25dfae448cace829e"
    "baca6b3c8a3cb64a81800614434895778c20d629b125b69f42945f66b644f3840bcfa6fce3"
    "61074256c50863ecca2ce756b4a9fb7e993d0f1fa48b2cc485b7eaa61405fbef150e7563c2"
    "150811767de0f9";
constexpr std::string_view kHex3072BitRsaQ =
    "dd9ec1cee6d8a971b166902c44a4f02ef37a62053b41288a1d873d399cbc9e7bd306ed9064"
    "87da2f49bc1c1809c0d4d88106d6879518ed925feb66aad5ff3c2b83466c554ed97b96abef"
    "55b3b02314f50d0385a0a1d8a46ae03e8fce91b412120f0a10dc681570fa564b6873bacd99"
    "7b616b2bd7733fb723ade23bc1089da32e509583436f1e3448b579fb21b240620d20458d08"
    "f0f995abacc0a398f0ab6a67c9f5bcf7e032fb1d668fe698d80327599ae3fdf3aaaab19baf"
    "17639443194be3";
constexpr std::string_view kHex3072BitRsaDp =
    "f1bfb40cd56573971acb5eb65b0cd2bf4502228f2ceca5a45c37661151cbfdb0a0a28233b6"
    "00fe727fd6ba71e9f1e15e4d53260960907fe01ce1d614ea220bacc8512541b786637d51f3"
    "355fd44222af7b0e2ed11d9454b4f7165234b2e8a62188dff3c9ef21ca1c16f70a83361507"
    "5ca2b9c28641398fd4f58fcf2650f752aa6a760cb584dd969cec80e1cb4dfdeb6bf1abb806"
    "61892bcf7dc28a5ea3309c8acf7f039e8af53f267d517a3737d2de1a9ca158fef171f8bda1"
    "e9a6f03b0912b1";
constexpr std::string_view kHex3072BitRsaDq =
    "3e3c2ae8d362dc9294e2dc71d2050f7ddfd9ea54d5c3028366af67be1a09cde7afe72e2772"
    "53c42dab632bf0842ca698f602d993d186e2904c676ab966c6fa3aadeec4d560032af5b0ea"
    "d10258e0412e5fad31855e6ddc1e3742da57840b3157e8e946bade6fc6fe45e57f3ba0a5c4"
    "0825df56bc761cda6d2693757c4bd318d414c527cb7414e351d7c49d8564ed379bc0084806"
    "cec50806e1c86728b7cd2b606212a43267bf694d6453dcc9e73f5b798a49a4331d263a2222"
    "154b5d834a4349";
constexpr std::string_view kHex3072BitRsaQinv =
    "18cc971e9186f86c144d140ceabbc9ae22c94e8d8575356fb6a4a033991ef210bafa39a4cd"
    "1abfa99b332fde9e56955af179459a7236a700b7fd1d88093906f6130ae7ca9742d9ed0d5c"
    "63e6a9e9b43df4d8b261c12d2c2f9148bc0669f165b8b881879c3ed58d4a6cd5a3f1193e9a"
    "bd2784609c01fb9094c7c822532ad7aec2a08aee9e263095ad0426455cb59258c7fd3731ca"
    "89dee31800d191ed7249721c25266650c46dcbfbae3070604d2e009914a2e269a01bafa5bd"
    "f8bba31c4f3b60";

// Extracted from third_party/wycheproof/testvectors/rsa_pkcs1_3072_test.json
constexpr std::string_view kHex3072BitRsaN2 =
    "d91f0d00f1aab580e2ac0e837638de7004fc968be21315a1ef2a234969045dd4bc1945eb53"
    "982eeb3fe97ce84a26c7d464784ff7e561cee570e26d4145e14ffcce70430ef32facd19e80"
    "ccce8a9b6604065ff1e50a7fa8fdd432ca4e7b2b858c88a96626e3a10a831596f91c2f22c8"
    "3e1a0267fc7df121d3337f3b0fa6a8c606ed9031c1f83b9213dea832dc5dcae9c03b478099"
    "53d75d966f35bcb10fffd23345a6ee2714c388972980938ad6123d9c97916920b9412ee1a8"
    "4e1d345b83866e2b3b02127384681aca038401a39bab5e4672d6493cd4a293b933252e3fc0"
    "6d8e4348f0e16b99ae58f7972b43bb6a7a04295d112ee509fafaae39de6d064f622c3f3c8b"
    "4fce6d836730c1285d90c548db62b795964794eaf143ad427360a2e83f5b1f8a20b08d18cd"
    "bd474f21c1bf42e6f1e137890df92888d83cc405975597209b7a09f4dc999fab82d4ebd77e"
    "0d66bd89d83fa564a03e3560977fb4e0fba7a0339f9221dc0c99402581cb95472a6c11b6e8"
    "0e91059fbc14470b7a68d8e50e53";
constexpr std::string_view kHex3072BitRsaD2 =
    "02ab95175be18395f033b981f8643ea816079d3a5f2f68e6b2f04bbacd65d659956ea22380"
    "c5b05e084d30d212876391c3228fa936d2fb1e6b42fda0fde10580d0712501fc0fac0a6fee"
    "999638b22c91041b0df8892684c78a628d8665916575130132566c1a40ecd7c9218b2d313a"
    "513934aa5eba95ca9ab4596e3a850c3253477cac7ffc338f5a5b34aa5b7773d5681dd2854c"
    "5d719a9f0d03162cff4b60246d48de48f0c26edd9d0f0dc1795c841176f3bcdd402a030f97"
    "684e87a4507bc8bd463eab49945ca8ccdebca2b4c5c8b15db40fcb12534cefd76c130e95c5"
    "806a1ca3fb4359477780f437877813ec9f1f2415f16b2268155a399213252d0b8837b775e4"
    "a2223012b20c767c794a4104411684590ae7bf7e4227949d59d94cbf85746d2fa690839865"
    "91e9b0af51080ab7c1f4bef0d96fabb7318e64a03a93ae62f52fc941ba3a1eb2bcbceede59"
    "3dcd6c4af0459fb77ab90f76ead70dbfb7249b17d62b740e2aa436f299fdb94071aa1518e9"
    "7ca6ba00f0148afcf316ddd507d1";
constexpr std::string_view kHex3072BitRsaP2 =
    "f261bfc097786e1c34d123c19cd0d0b6cc65bef52720c8a003892b0e74611888099ab96c03"
    "2a078b77e000be90d5b98fb8e4083cd9326adad050ec6cb92f55b5bf8066b1065e3fbfd133"
    "eecdacb75cceba6673d2184ba9a0a95833fb7e0c27c607777947eacfe702ddceedf16a65fe"
    "978ab5355207808fa2a590f1733b99d9164962ed5cf98b478cd0288ff161943ad1a3fdd135"
    "35c752f622cf8e0c5c3ba43abbbaf901dc457faf11e09222473aef53d176061fa3a70741ba"
    "b8d540a959e1c7";
constexpr std::string_view kHex3072BitRsaQ2 =
    "e551f8c7ef3718c07aa9f5127a3fe8439e70fba743524267355f8095af64fd7c0b4756cc43"
    "555bb6157a488046f1cc9988e71694164116b250283dd50b7894a456918d6cf8e83bfe085a"
    "be65bbefe791cfe178654891ab82d66f70c85a757573a051039605363c38ab9dab31110a93"
    "c73fa09b6f71068633ed8fd077ee805c02d559090e346a28d7186a6b5f6804b65f655b34a2"
    "a6c46b81501b2b47154ceefe6b6c20fe73cdf764fc768f724faf2948b270e6b52518710464"
    "76d4390b5e2f15";
constexpr std::string_view kHex3072BitRsaDp2 =
    "75c5914a9f4ee111cb88237b9c1aca8f47d9d8637e53aba8348f9de0342449ab301f82213d"
    "985a7a26112dcb6accae916b2141ef6f09d469e5f6ac2a5800ec0097c068257416af9b20a7"
    "bf4d28b31fe143292cf5d4e04ed7c5f119b1059a1a695a8f6edac6f9a621fa6ce5a8fc2dfa"
    "fadf6715357a77b9532a67b72a6ab7628835b85fe5614b8fc498105d80c80d225762fb9d7f"
    "e155acb5f44c2d954beb9eecfaf2eab340b8744638c589bc262838c9dd691fa897f83cca6f"
    "54082a971f1959";
constexpr std::string_view kHex3072BitRsaDq2 =
    "119d4c48bf3d322f86bc8b5092075aa5e703b2b0d460fb2cc652c1a3bdc73a194f1c79b452"
    "efb98db0f4a5a104d209ef392ed6f3250a76ddd77e5fd17f821198d5f574318ca4fa06b749"
    "911a6b67301869295e801924e751b37af7e4cbddfdd995d4e33ba0c6dbb556a953beff1a1a"
    "e3d1255b0b225967f1912bdccd798a6e86e130679ba9b705d00fd60ccd55461764187afafe"
    "0b654704b5cc80748354577f3f6d1cd3aebd816546672cf990d9598875fc6a1c3bef36af29"
    "b05ef8cac0bf49";
constexpr std::string_view kHex3072BitRsaQinv2 =
    "999fd604b8158fb941618917240546c32a734ca8b4877d9cef9743887cd34a1d889a0beff8"
    "ae1bc304061eb39d569af5fe0b2646b6d1ad7dac7a379ec695a8e9ccb44ce4f1c1178cf2ab"
    "d741afcfbac9f2f8b7493820677347bdf08c16b481fb14d2a357823bb6faf2b3732830ff27"
    "be7ebec8e6a325ccf1e8c24a529bb5749821fdeda8b25528fda0e473fbc5161b764b848135"
    "989c2bd49914bb6d24484c81821bc30aa1c4a702b22f144cb2f7c359c1a68d7559c00f805a"
    "17cee23d283d19";

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_test.json.
constexpr std::string_view kHex4096BitRsaN =
    "00f601be0dccd04aa40b12f3f191ae17c1f9c8c0b68e7a77e14be25c3c7907cb1d33a6ef41"
    "8ef41852f32c98392bc5c9aed91c1a1501c503eab89b3ee6f4f8eb2e0fcfc41bd03609cf6a"
    "8eb3aa6f0fbe23187b33db4d34b66d128a8aba0a2abf40bb9d13d8e2554569a57ab1d8c61b"
    "8cad2dc88599ae0da5346e15dace1bac7bf69737c22f083be9b46bb8b1eab5957b2da74027"
    "5e96c87195b96fe11452159dafcfd916cee5d749a77bc3905a5ebd387ae445e8fe70f16e9a"
    "086639779ceffbfd41557bd99aea6a371a6b4b160615a1a12bc6958d34bce0c85adcbd8392"
    "fa10ceca52209d56196ba3d273ce228f1f111192aa92de2a039798a17bcecb4dc6100e6f8a"
    "e8c2643f2ae768b2255f082c978e95ca551555f10608231cf8003bbf807969fff1e51914b9"
    "a8c9b8f4564645b9e5d705ffad29663f5dae3d76652b422e43f13e6c1491090805c2d1268a"
    "74a251177427e33a9a91175c3670b91746008bce1fd231e6e4f2ad70cb43aca5f07600a6d3"
    "1dd02915243dfdd943a02165da367a6b7e4dae1dd2e8b836903080795d2585076cc1c15dd9"
    "e8d2e5e047526569b1bfd395d957eb9fde325d342d14426e71efdc1887515e53cdea583492"
    "1f928629e748eed097ac4024e2bf255d70411f87373948cf8e8aa7effa2b0ab47d5166091e"
    "1aedec60568b155bd9c27bc55f3ece35f83d636dbcd5abf4853a051db94d5045";
constexpr std::string_view kHex4096BitRsaD =
    "065028224431ca35e87f82d97302c9384b4d341385ecd8510f4df94e51facf0dbfa0169413"
    "9e3f00e34859db09bd087e74b2e1c1229652e73df7e49c2fb2dd9cda7f5b49d81a32e9403e"
    "4b97b6eeebfdb6e89e7d8fbf27b95282fca9668e649c68297bf367bcdc21a86dfc22132a17"
    "7e4591024b5dd49ad091775271fc9d7cb6e8cd8a5858f93f4cf280bf0c1b69d675e6f760ab"
    "443fa8ee8ddf89a2a85d46a52c367c27db6d1ec6435e52eb86c7e0ab02b05543865423cc4f"
    "25346f55e1db6675e69832e43a04ccc78af3abd68477ed37698ab7f61facbdbcdb32552de5"
    "e89d8342aa9f445b8afac81bfc5bc05981ea20b340e948f710f7b3ee85f18b5c3c5832f233"
    "6706c5e9c9bd8e43d202e73a0f62776df4b715975eddd31aa643b14145057b4995556de614"
    "c57b33297bda0e05a8b8882a29563bf21686ce34c3960f905de73911987eb696e07eac0a63"
    "857e2894c3b4629477ecbf1fc76eafbb2ce4a0f00f8cdb6fbd6169e399151460522cf5b365"
    "d9bbb9587d07dac8c438982adea9ff243a86bbdf128eaa0d3a88871d8cdf081854258a651f"
    "f4226ee9749b4a6add090c159ccea06b9a10804e5fe15120cc63a5972eab0e43980dedaff3"
    "21fadeea3ca60c3ba1c2980bb597ea783b80ab6eba87feb5754fd1d65d7cad6f81cf52c1a6"
    "bfebf9a75e9a316cb364d8cf467d96370871df2ee66ee1c1694a0223958391";
constexpr std::string_view kHex4096BitRsaP =
    "fc21b855c5ad4ca2b6970516406f71c6e79efc4126e6598772db1e082de6b0dddaaa2a2951"
    "f04148e86e0bde28213b7f600f987308301eacea134062bb0c3ddf628da9abf93ef1ce3e75"
    "b0953a484dbd3554bd5c0649933dd77e527563e90f05a8013fddac958c329378e94303b304"
    "be5f9df1fe5b043a7fdd94700a3f0b1cbbd0516b7cd94c57ca96d9fd2a8ca973991218cba3"
    "3a1c23d810f7519d1f7702ab72affdb3f84a1b2a88116e4033bc4d0cfc7989c657e0fe94e9"
    "64476ae58bae6b7876f36c09d32b1a63f8c47c94a74c92eedf75fc27cffe0f8452363e4bc8"
    "f7653f3cb55eaf693cec70d13c875de935a8b20439ab7e93f76981c5957fc5bb44d9";
constexpr std::string_view kHex4096BitRsaQ =
    "f9c7f748a505d23ecef9a85f8097c8cf7d7028ef6c90e22a336511582d2cc3636e34ead372"
    "04dbd22f142a3fb1d5f857b0310c7a433f51ae14d4608b01b43aa8c7ae67835f7fbe0b9d97"
    "948b39e9ba2d3a1687edb8b56ee70ff0536dab4d0551f71ed0daee9e412449f5f099bcc15e"
    "4ef0554dc79f87fec5a0dea717c7054392bf444613937401bbef3c22fbf7e738c58779b981"
    "609a1f9c11dd6f0bbe9996e2773459e4cef247b02a9fc21296ac57a5b10561824310cfbdec"
    "c90e06598370e3698713fdbe2528ec4ef3dccaae701eedc3e54ad6e7af4e68e3b39bd2e97a"
    "c9119936c647a503511cb283df984cfd7c07f0f56aa8ae3166948ef3f41b0859934d";
constexpr std::string_view kHex4096BitRsaDp =
    "815486aab0a0896bf97f13e3eb1f7f5c49195b49cc3b6277412a3688798b18f46422df479c"
    "b941b3b54e25964a3d69b897bcc8355160e58b4af29f1745dd2cabb670f634b9c058e6b351"
    "4947f2c27de5ed424f73b1e1f1be4a188911a0333f3a6688658b3ee8e3265a512e4deacadc"
    "470ee304ebb5224123afb461984fe8524fe0b6b30d32a59f6ed2dc74a96bc7cbfd1bb44e58"
    "a7092235c5d6272e12a2c862cb8c8cf5d109aa4fb1c6472875a14460c1ed5207c4b22bc494"
    "c7947eb7ca63a8cafd31361d000ddf16a2d79f13dd9140d979149b488cbf44945a5b6aaf13"
    "221bf4491ebbb7fca27ca20e221f49c3c37b89fcf2dc0e2cb63f8f8a9b7a14225059";
constexpr std::string_view kHex4096BitRsaDq =
    "b61d84ff934a4e437b16ee1b4b9fdf4ae13370b5385bde7a5464a123c0343df575f9e128ef"
    "9df944230d39cc9cf5dc0edb28b7e740b69ef024c1bfee39fcd5340ffaea0010160c535dc0"
    "920e7cd81be533d00fa554a1fc4d3e02c461569f5e7ca787f1515edf45b196b759884de652"
    "c38d5934cf92524e807b4d3b590bc39bc417ee4885a761d28ddadce6c8fdb3b961d3e7fd48"
    "064df9340a967f8b79997438841f48579a476ddb55088c308f68f2b29d01c6597a5a7c8d06"
    "6284f63e37a68c3879c32aa3836675fd0eb2719883a91944561e9dd7e8aa6bb17157f08c48"
    "f8e6fae5c3e5a2bb6b5d580eec6c97ddcd9be0a49ef283a7031ad7aba8d438df4e95";
constexpr std::string_view kHex4096BitRsaQinv =
    "22fb8e5fcd9b767104e71244db53058c18061e1b0d1f63b73e2d59a95e2a10cd87426a33da"
    "13c287cdef8136e5e47e93fb9b30ad92628a7b543f48eb011a86356ab3cb480f27e391b018"
    "ca187d97af3d82e31861ecafa663db78aa89c3bd468e6aadefb3a43f78bc00b8014c95db54"
    "e9d21a017e8f21f671545edde9a965ea32dfff45cda37fca1aa5132f6c8eed222bd01fed5a"
    "6e7d639580c5955777a86544c2c4c939bdb8b4c486dda53072861a0334359bdb3758475e49"
    "d90d0539944e78cfcfd8fff55bb31a1cebc65b28f51e790701b2f7912188984f034e6e96e1"
    "c5251e33fe38fb221bce7a90a86857c5f56b6ca77307c45d5290b1f088ade082b349";

// Extracted from third_party/wycheproof/testvectors/rsa_pkcs1_4096_test.json
constexpr std::string_view kHex4096BitRsaN2 =
    "a30b62740e25aab01934ea6d9b92090cff2c0ce9831941eb98376a2daabda6afce254617f6"
    "dc579f97c299fa89ca5f746fe3693075a135774b703b008b8e884ea6ea25a5cc6b92f9b328"
    "d77139401090fae69ebe327b36636306ff8b4a13e6e75d43eb6cf856a888442a9e03a2bbc2"
    "2d003fe97c73fde4a3a6db1c56e1d5c8fb5e5c937d60e2752954a0bb194a2b84f50a12be18"
    "3493b8035ff56b38f1b40ed3885cb864749342fb7d577ed5864bb42fd1b31e2d40e23c7192"
    "335c9a3fc6b2870c9f3fb3037cf21c6cea27f39696f561ce0b60b5f0df94bf965e8364d8c1"
    "fc1ea69755ee65540e051c5402ac3d93a1c65853cbb4231b6619afb07b58e7c7898d2f0efe"
    "b119899ab7be7f5110e7ffcf97a226bc6df9b5ac7e21645369dfaf595d05694695e5dab014"
    "ed1b0686ae065743a4f97f15a92723990c69c88adf0427e3f5c35b5612d1038151e5e4e359"
    "de850e910b841b2d58c2febb5c773e707d171278f2e9b20d1f4fc05274f6043024ea644b8e"
    "d7cddf5d7f7a4036630ce3220eca913fcc4d3f63d8036a49a76c0b9c3d3d815f61d98c37c1"
    "2791fe300fc39a9b05ff28a5c5f54070f029b5d4214e874912c392bd92e9c870a6707927a0"
    "df866d872dcfc7b0c133621ef1f1c01dc485920a66920a815cc35f4ceeda40e5dedef32aa6"
    "5436ef360e4c10ec1c970c5990f6377ee16804c9f00f6a7a751c6fbce973d1";
constexpr std::string_view kHex4096BitRsaD2 =
    "50dbf689c3f25e42535df0dd470817c10053e25b748ef4285927325b4f901ab899add6a34f"
    "e45af8651537b40eddf49514605dec9089d0b0471373cf8366bea6f314b073177c4a39d7e6"
    "6b625598361f10af8b0e9c8e8a9ca3a1f6de2770d354eee61e3dbeb38b8578f901c09fd62a"
    "2893351f207f8decf4546dda12249217c8c2357b57f4d29a7452ea1ba0212e9013ce591939"
    "7be9be9abdde42bcccf21560470264d83d104369e1f1a08f58b8f6b5b873f28552e6603f9a"
    "d82a16bd865747aeb4d3ac7e105b2a49c19eeaa946588f96d601b279b1085e33becfbf15d8"
    "aea6accbe4ec0408b9a343374ed408fdcc7f4792d735912ba76919be968db2f53c7ba334d0"
    "fa6c780eda7b36f437337b4734e8dccbb2e92cb0648cb7ee48e7343eade2efc0103a7aba8a"
    "3686793cc93f47a62adcd4dcfba7a22c4436638d4e8f50b4248287ead7c8cc9c7f5d8c0067"
    "5ac06bc7fc8c5559c73c3d0fa79a70c5b1f49096b1901141629c52359600fe6520c2b3cab1"
    "7dd81f0245a2b33855ffcc8a7db394815b6b77f4cf6b33319167df390252b7c99ea4abac00"
    "2e0d50ae7c046d5631e1f023ab50b0517980eb0ca232bbc74b297acee280ac52b8aaf795b5"
    "4c9f93b8c97ee6667d08ee798b0910a4038462ffccedf4ae65876afbcfa744f52a8340daeb"
    "a2b670c0fbdd8d8f96fc95447d4ede3f9b624722f98cc4ec4aafde697822f9";
constexpr std::string_view kHex4096BitRsaP2 =
    "db20bff0f553dc176de86baae4b93ac95673c6f715bb3f11b848bec81de4a0df846121b638"
    "5aa256cb2a9e66996596a1b5b532257cbf078819b8bf3bbf7801441801abfe490ca84e5d74"
    "82ee6211f04d8304be122684d1dc8cdf72d14bf85bd760ec0d0f5030e5ef62a0ceb275a2d5"
    "7d95f3d63e39e4d2a97db0e243793bf32e83030cc0a0bea38824e6d1188b41703cc29a4f60"
    "028d895ecf64a9ccb3b228c7e66cb1db316aed92433c63b0445f1cc03460e33440ed2a23f9"
    "01eec8925e7671e302f7d226a5e741e82982e67c58419e22105319ceffce9bc26ed89f8b59"
    "042b2974f6097f423a22e2656702b8d8813a5fde557d6adb6e7fa4e58cf8f0776973";
constexpr std::string_view kHex4096BitRsaQ2 =
    "be7ac2633836593c891975dded137d40f9e18519f92333048f1181b0b9ec1207502f5c5f0d"
    "1cd58365bff3e80b350b01990b1ea85e263f8adf4b6a99eac132554855d255c2253bbaf722"
    "e41b893c81cc9933560068b226e147d459b9a73ef1af2ab96a2b39a9e401385a713a860abd"
    "3b6ad9157dd6c2508f1859cb84717d4d533a7ad0ae92734e085956c40a9fa612555e68247e"
    "672523868e06cdc23e62524537435a142924c7c466b2cc89ef281c230ae6fe123ae92489e3"
    "83407e6db9e5a859f8f7d6e3a68bef914494420226fe4123049c324eb0dccce0b7ee1382fb"
    "b90b03d87aaad596d232be352d83e0a01bac664ffa948ffce419806b68029c50ecab";
constexpr std::string_view kHex4096BitRsaDp2 =
    "abdb408e336a04b85f5ba46d901af1cf0c3d9b3317d915fac8c44cd4581582522ad99efdf1"
    "aeab995497e549644f3757365298b4abe48a7ca467af9ba56bf1da3cd5bad5a0e70b6d0280"
    "a95b5a90e51d757f17aed684deae91d181944277d357d4ccece530a858fd6925e356354a73"
    "139eb27139b6600f141cdec865d0c442d21cb01ca54aac9946e26220659679c913ee2fe5c6"
    "cfd9bf7e1b3bc0ac29d6b58329e5df8ba07353459df3d3df5f9014d56d7efb5275054c4290"
    "3d82cfcd73c683455e838c4f0158a0e8fafd8dd4c1c71cc56c76304c9775abd54ee81820ca"
    "bca9394760db4bf25df4140921441242c2ff4c46ec5783a1fb44a2c7e1cb2f95079f";
constexpr std::string_view kHex4096BitRsaDq2 =
    "ad74dccfbdc0c0428016cf5ee925764a554329121dee0fe776e15a58b4f664f483f09d0d71"
    "c3702bd7dc95201a14939140ecff5e135e813ed558b81ab1cc7d296c55bad49d978a6d17e0"
    "8e19054034733c8fa3217c35bf722717191e174f1a8789408f8e0d54c86cd4048857e2f8a4"
    "9a1712d89f5f925409fb02ca72316709a360fdb64b42d1fd9d5cbdc6886619b55848404dfb"
    "4db2644783ce6e5114be346d138621e17a16245495b0fcd21f17478821c57858e18cadd963"
    "7582a59f064a3ca4b233ff5c0fae1edb0ab877e3bdde8b32786044efa3df6e32b54bf838af"
    "4232e5ad9d0734b9c370b2057b0d3ce09052ce58c6b7c2e7685050c17e55e2434f41";
constexpr std::string_view kHex4096BitRsaQinv2 =
    "9479c2cb8bcf71d5edbdc4f65240ce586e906ab636320420cf1906170d3af01f767fcab768"
    "880628ec27953589454a0294409f78127666f45ec07d38139b4445c7638fb39dc18a91af5d"
    "9c28ecb47f9cebb1ce19e48dcbe261056eecc107f6d3ca715f3747af24e6ae6a658c434a68"
    "cec6ad84664c88167cc25567b0cac2302ab109c66bd339be5158c67472a01a81e9cf19dee2"
    "762bbe9b0eafdcbb96991070d956db3007cb2b4d2b0acef96a233ff8ddedb970c11c0987f1"
    "b3bc1ec8b1d95a7e10644c94fe6fb670d363869496d0e25ccd9564f283f55982f9c75108c4"
    "70c81bf3b8f28c7e8533683d4945b538c4d683083610a7579f9e8dd1e0c8b15c5b8e";

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

absl::Status NewRsaKeyPairF4(int modulus_size_in_bits,
                             internal::RsaPrivateKey* private_key,
                             internal::RsaPublicKey* public_key) {
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  if (BN_set_u64(e.get(), RSA_F4) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Could not set RSA exponent.");
  }
  return internal::NewRsaKeyPair(modulus_size_in_bits, e.get(), private_key,
                                 public_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEd25519PrivateKeyOrDie() {
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *parameters, (*key_pair)->public_key,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key,
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<Ed25519PrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateEcdsaPrivateKeyOrDie(
    subtle::EllipticCurveType subtle_curve_type,
    EcdsaParameters::CurveType ecdsa_curve_type,
    EcdsaParameters::HashType hash_type) {
  absl::StatusOr<internal::EcKey> key_pair =
      internal::NewEcKey(subtle_curve_type);
  ABSL_CHECK_OK(key_pair);
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(ecdsa_curve_type)
          .SetHashType(hash_type)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters,
      EcPoint(BigInteger(key_pair->pub_x), BigInteger(key_pair->pub_y)),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->priv, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<EcdsaPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss3072PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    ABSL_CHECK_OK(private_key);
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  BigInteger modulus(
      HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaN2 : kHex3072BitRsaN));
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaP2
                                                           : kHex3072BitRsaP),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaQ2
                                                           : kHex3072BitRsaQ),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaDp2
                                                           : kHex3072BitRsaDp),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaDq2
                                                           : kHex3072BitRsaDq),
                             InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaD2
                                                           : kHex3072BitRsaD),
                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaQinv2
                                            : kHex3072BitRsaQinv),
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsaPss4096PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetPublicExponent(kF4)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(48)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
        *parameters, BigInteger(rsa_public_key.n),
        /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPssPrivateKey> private_key =
        RsaSsaPssPrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
  }
  BigInteger modulus(
      HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaN2 : kHex4096BitRsaN));
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaP2
                                                           : kHex4096BitRsaP),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaQ2
                                                           : kHex4096BitRsaQ),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaDp2
                                                           : kHex4096BitRsaDp),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaDq2
                                                           : kHex4096BitRsaDq),
                             InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaD2
                                                           : kHex4096BitRsaD),
                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaQinv2
                                            : kHex4096BitRsaQinv),
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPssPrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa3072Pkcs1PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(3072, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  BigInteger modulus(
      HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaN2 : kHex3072BitRsaN));
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaP2
                                                           : kHex3072BitRsaP),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaQ2
                                                           : kHex3072BitRsaQ),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaDp2
                                                           : kHex3072BitRsaDp),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaDq2
                                                           : kHex3072BitRsaDq),
                             InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaD2
                                                           : kHex3072BitRsaD),
                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              HexDecodeOrDie(key_index == 1 ? kHex3072BitRsaQinv2
                                            : kHex3072BitRsaQinv),
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
}

std::unique_ptr<SignaturePrivateKey> GenerateRsa4096Pkcs1PrivateKeyOrDie(
    bool force_random, int key_index = 0) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters);
  if (force_random) {
    internal::RsaPrivateKey rsa_private_key;
    internal::RsaPublicKey rsa_public_key;
    absl::Status status =
        NewRsaKeyPairF4(4096, &rsa_private_key, &rsa_public_key);
    ABSL_CHECK_OK(status);
    absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
        RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(rsa_public_key.n),
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess());
    ABSL_CHECK_OK(public_key);
    absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
        RsaSsaPkcs1PrivateKey::Builder()
            .SetPublicKey(*public_key)
            .SetPrimeP(RestrictedData(rsa_private_key.p,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeQ(RestrictedData(rsa_private_key.q,
                                      InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentP(RestrictedData(rsa_private_key.dp,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrimeExponentQ(RestrictedData(rsa_private_key.dq,
                                              InsecureSecretKeyAccess::Get()))
            .SetPrivateExponent(RestrictedData(rsa_private_key.d,
                                               InsecureSecretKeyAccess::Get()))
            .SetCrtCoefficient(RestrictedData(rsa_private_key.crt,
                                              InsecureSecretKeyAccess::Get()))
            .Build(GetPartialKeyAccess());
    return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
  }
  BigInteger modulus(
      HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaN2 : kHex4096BitRsaN));
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   /*id_requirement=*/absl::nullopt,
                                   GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaP2
                                                           : kHex4096BitRsaP),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaQ2
                                                           : kHex4096BitRsaQ),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaDp2
                                                           : kHex4096BitRsaDp),
                             InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaDq2
                                                           : kHex4096BitRsaDq),
                             InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaD2
                                                           : kHex4096BitRsaD),
                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              HexDecodeOrDie(key_index == 1 ? kHex4096BitRsaQinv2
                                            : kHex4096BitRsaQinv),
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return std::make_unique<RsaSsaPkcs1PrivateKey>(*private_key);
}

}  // namespace

MlDsaPrivateKey GenerateMlDsaPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();
      ABSL_CHECK_EQ(1, MLDSA65_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87: {
      std::string public_key_bytes;
      public_key_bytes.resize(MLDSA87_PUBLIC_KEY_BYTES);
      internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
      auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();
      ABSL_CHECK_EQ(1, MLDSA87_generate_key(
                           reinterpret_cast<uint8_t*>(public_key_bytes.data()),
                           private_seed_bytes.data(), bssl_private_key.get()));
      absl::StatusOr<MlDsaParameters> parameters =
          MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                                  MlDsaParameters::Variant::kNoPrefix);
      ABSL_CHECK_OK(parameters);
      absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
          *parameters, public_key_bytes, /*id_requirement=*/absl::nullopt,
          GetPartialKeyAccess());
      ABSL_CHECK_OK(public_key);
      absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
          *public_key,
          RestrictedData(
              util::internal::AsSecretData(std::move(private_seed_bytes)),
              InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
      ABSL_CHECK_OK(private_key);
      return *private_key;
    }
    default:
      ABSL_LOG(FATAL) << "Unsupported ML-DSA instance";
  }
}

std::unique_ptr<SignaturePrivateKey> GenerateClassicalPrivateKeyForTestOrDie(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm, bool force_random,
    int key_index) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return GenerateEd25519PrivateKeyOrDie();
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P256,
                                          EcdsaParameters::CurveType::kNistP256,
                                          EcdsaParameters::HashType::kSha256);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P384,
                                          EcdsaParameters::CurveType::kNistP384,
                                          EcdsaParameters::HashType::kSha384);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return GenerateEcdsaPrivateKeyOrDie(subtle::EllipticCurveType::NIST_P521,
                                          EcdsaParameters::CurveType::kNistP521,
                                          EcdsaParameters::HashType::kSha512);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return GenerateRsaPss3072PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return GenerateRsaPss4096PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return GenerateRsa3072Pkcs1PrivateKeyOrDie(force_random, key_index);
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return GenerateRsa4096Pkcs1PrivateKeyOrDie(force_random, key_index);
    default:
      ABSL_LOG(FATAL) << "Unsupported classical algorithm";
  }
}

CompositeMlDsaPrivateKey GenerateCompositeMlDsaPrivateKeyForTestOrDie(
    const CompositeMlDsaParameters& parameters, bool force_random,
    std::optional<int> id_requirement, int key_index) {
  MlDsaPrivateKey ml_dsa_private_key =
      GenerateMlDsaPrivateKeyForTestOrDie(parameters.GetMlDsaInstance());
  std::unique_ptr<SignaturePrivateKey> classical_private_key =
      GenerateClassicalPrivateKeyForTestOrDie(
          parameters.GetClassicalAlgorithm(), force_random, key_index);
  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CompositeMlDsaPrivateKey::Create(parameters, ml_dsa_private_key,
                                       std::move(classical_private_key),
                                       id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
