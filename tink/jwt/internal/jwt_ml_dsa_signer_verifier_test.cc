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
////////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/jwt/internal/jwt_ml_dsa_signer.h"
#include "tink/jwt/internal/jwt_ml_dsa_verifier.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/jwt/jwt_ml_dsa_public_key.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace jwt_internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;

// Taken from
// https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/mldsa/mldsa_nist_keygen_44_tests.txt
const absl::string_view kMlDsa44PublicKeyBytes =
    "b845fa2881407a59183071629b08223128116014fb58ff6bb4c8c9fe19cf5b0bd77b16648a"
    "344ffe486bc3e3cb5fab9abc4cc2f1c34901692bec5d290d815a6cdf7e9710a3388247a7e0"
    "371615507a572c9835e6737bf30b92a796fff3a10a730c7b550924eb1fb6d56195f02de6d3"
    "746f9f330bebe990c90c4d676ad415f4268d2d6b548a8bcdf27fdd467e6749c0f87b71e85c"
    "2797694772bba88d4f1ac06c7c0e91786472cd76353708d6bbc5c28e9db891c3940e879052"
    "d30c8fd10965cbb8ee1bd79b060d37fb839098552aabdd3a57ab1c6a82b0911d1cf148654a"
    "a5613b07014b21e4a1182b4a5501671d112f5975fb0c8a2ac45d575dc42f48977ff37fff42"
    "1db27c45e79f8a9472007023df0b64205cd9f57c02ce9d1f61f2ae24f7139f5641984ee8df"
    "783b9ea43e997c6e19d09e062afca56e4f76aaab8f66600fc78f6ab4f6785690d185816ee3"
    "5a939458b60324eefc60e64b11fa0d20317acb6cb29aa03c775f151672952689fa4f8f8383"
    "29cb9e6dc9945b6c7ade4e7b663578f87d3935f2a1522097ad5042a0d990a628510b6103cb"
    "242cd8a3afc1a5ada52331f4df461bc1da51d1d224094e7abed3d87d98f0d817084780ee80"
    "370f397631ecb75d4264b6b5e2e66c0586b5fb743516399165837a0fdff7c6134f033bfa69"
    "c1b2416965c6e578592f40e258cb6dfb29fb8e0f54355b6e24a65f67abae3193d007115cc0"
    "b9ff94cb911a93b1a76c0e7662f5e2b20139e0159ed929cb932d4895f89a02e55c59df2dbb"
    "8f6e5dd7d5b1f3cec37b4a9166b381c5440e23e67368cde0a29d59aa05a3c9be24a4dc8dd7"
    "5be30e82bc635d36aac66de880c6701a987d7e05f0f2ff287828bec30595089d8ab9aa390e"
    "d719caa6e576cdbbe9b184a322e5e2dabb69c23cc696d54fc32ff57001b6b64e2a837f3062"
    "d85aeb50b3510f7edfc34df38e083d4d9b94ffab0de15d73d9af30b9f31cc4f41c9c24f2d6"
    "18b2a7c3c4bdfb745d52d3eb54589c8bda8ac05dad14ec744505575a0988eec651c1715439"
    "fdfb29923380a43c1a66a86c982a841f11820a6a0e1e2f2fff5108ecae51a6aabc9b949226"
    "d228ff84c4e5e5d63114d80359c4931e612dced1838b7d066ac9182cecfa223a21a4c8e155"
    "aefa780373bcc15098aee40c033af22f8e7c67a0d2526da7475e830308c04aed9d32bccc72"
    "e719ee70a8d13f09ac11e26ea237d5cc8f98b5ae0e54f933bd0507942ed900d056fd32f8e6"
    "e81777912fd482746029b71cce3ba69b8fc2d03eb441027c387bc2f95031a0ae7052215eb2"
    "4b9ea8fb0a961b0f80bfa80d0d6257c1c22b508c5d31b97fcdfe1d1766e8a9c8771932dd59"
    "8adb7e717743f45fc571f21e4a516249f81d747f15329790f0f70a0b8e461a4edf50504af0"
    "3f30ddf8a8818e38761e1681d6ddef0b1dd326b2ec228ce48570f285b49d29d7c2ef37866d"
    "5446df82b8e43b34cb248962a21a9a3946159740f8aee8e6a16a4eb2b42d143fe2612e05ef"
    "4b5e646d813248444556a2a8bf92ce10badecb6b8a40b080dd42d53346fefcc4b9b40b1e49"
    "98991ec753c95aa2f2a506f311e710b0f1d36c1dca6644ee6d1d4ae9cea5666ef4b3e888db"
    "dbb95a77ecfe1e8b477de7cb07639d682d53020ec14ea6c7dd7e715389d10938429fab8a06"
    "8a1466a4cd891359f8074e0f5a142add731b87878d985e4fa6ecb3b73d298553418273e950"
    "3aa84092c080e5f2902f90f5c59944d24ca0271d11d0d6734606d039550a37fca2b735850e"
    "63f540f2f06b79144b5c4ed2c700bb51c33d265b3d037389c99efd597642d829db1eb58643"
    "cfcd07f4dec60b8f727d97bd7c4b59bda1";
const absl::string_view kMlDsa44PrivateSeedBytes =
    "d71361c000f9a7bc99dfb425bcb6bb27c32c36ab444ff3708b2d93b4e66d5b5b";

// Taken from
// https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/mldsa/mldsa_nist_keygen_65_tests.txt
const absl::string_view kMlDsa65PublicKeyBytes =
    "d2fd03f3a1b7f635af9f34d580a98f524c735bd5ba2355dc6e035bd21765580cbb111923f1"
    "94a7cc8a7bb2ebc5c0e71aa637cc800e6103b850a539b2a39e1b6d713e5db8314c9ae1f8bf"
    "8a38f06afb9d73b161b0ffe3a4891706ae26d54ffb496df8dc0f1983509500c9abbd28e59b"
    "3fcdabbdadabd45ec31499378bde849e7c1f19b7044d67e05106d7136d95380d5605d4465d"
    "877557065df0a75d3c28542f40feed42ec7e280637b083d988bca5f6394e02396c4676184f"
    "b63318dafaf5bbdde00e308fe84019c2340a3f3e1c0865624970711283356ae14bd6b94d1c"
    "9ae188de1a8a2ca824a8eae2fe6afb38d83a2d99996ab21fe3e84c0be6b6da08879b677374"
    "fa7c691b13d40fa9d4cc26b2288d5a8c9a43724381004d61b0d57ff400314c8e30ee796af1"
    "0f7ee21bf13d08180465abc72eddb080c6a07184e3eedc47c19aa7f09d1f3309e183a2bd9b"
    "0573dde474a81ba4f78d0c523d0c04f90060fd571a35c037e079c5e210d7390df568f2e2f0"
    "3ce44420c82f3fe69eb9b48ee90962d6b0f24440648f71edb241ee6566fc1a64cabf66be6f"
    "ecbcb1387c82a7bc202d9e367998e2a291af0cd1570677fe8d63a3285a2ea6eb29af9dc1ae"
    "c1c36c4706b12baa20839692f286a6e0321468f7479345c4d52fbdb2f06725b554b89e2492"
    "612681acebc6c7bada9225818dbc35d64c22c48bff80a730d0716dfac99dfd5b8992611d0c"
    "93ee90bdb260022afe25d913e06effb59cb1f8a60cbfa5ab2f459a16f467e989525e0a37eb"
    "e56e833fde55db9d1530adcf45846df281e47caa1e0a27efde2107d354cea0f6a454692f04"
    "cd838ebdd46e191e5d9c11839a2c3f488a4fc7cd265a7b5d32b08cbdbfab9d2ccd76222c8e"
    "e37ddcbd2aa063ed861473a6454caea377850b1a2b9ddbbcb374fab5b12f351c8e5888872e"
    "5cd1f60a4fae1ff837d192c22beb41ee6fa392fcdf4550ff46b5ce906d017ef3077df13230"
    "0d8bbfa9bb03c75e79e2f04c284ad06a44399649c3e2a2a8d1efe9b7a4e0c271047ab75908"
    "bff7df9e30eca547745bae23a86ff9a8b58c2538b88b866401076902dc5f0bd761687b49ea"
    "fe36d350cbedfdd36c121cf23786bfcf7e47076496eab6bbda774049c2ebabe2de99c4c24f"
    "2db73684015b373977496760cf9ac23d8b623133db2de10d73fa6ad1c6dac8434f28c6e251"
    "ce7293cff3f3b61efcb5a435123670f29846a13df3ee712604461f1bab8f4ebc836de05897"
    "8ae734396a98081b35cc98188a86949c99270d4709854c5b35b17f48a373134c814cc8a0f3"
    "e2fa807f2a918530907864778282d75e03a41b2504eed816a417a3ac6ba16080c39b731019"
    "2002a728f7f20395009a9e16767ce1971f5de7d229a50613369e4382045a8e81901f4dba81"
    "02f3d413fe35b326a874f233b719a7137600d35d33aeb6b7259624083aa968730c8f78292a"
    "d28f14eeabe660835984fe69ef23dec8c327c0eb0b882d587e1ec433da85c9fd1e0a34994d"
    "ea240c854452d18c30f496e49ec904b602e0f5062edcda03280a53b4313574cc2c0d5471bc"
    "9613bdfd6641f5bd127bab5b5eb3d499a33114048220e819f8ee12ca922c8f17d9c9f51ad5"
    "bd6883b10e6aa2483ba49dc547da7686151344f4e9099b38e430b5226b059832cf03db48fb"
    "02dba4e61593dc4576360491890e53ec0e6ac73cf32b25d823b38456e286505a541e5aeee9"
    "6b1914f5f76687ce2b0160227abed77993594bcd831366206d75714082f1c46f1f4439ac81"
    "a57af31c81c555307a070ffa94e0479b784bbd88a60cd4c7cfd94e6afe02f6b21f72af0dcd"
    "6609d40c965c14e5f2389183e53de930f7de1d44215cf49144844e8b87f78a7f132aefe22b"
    "e80b4e3a05ee3a68ccf609ef44047402e4493046e6f9c767ff8a75e28b3ce077fde7e7eed3"
    "13b5bf7e460127ca8182e9bc794c0dfa730fb920080575a751b5caec85a109b4422ba26674"
    "3f0d032bda8f1ca6248cdb917530df1302a5f8c18dc642d52478c98c12a3f16ef2b62b4f59"
    "ea1bb58de7b65b3c7153ce6da5e4950746f80e087a0e3586d097791bf36def865d68591d39"
    "d0903773eea962147f34704138b54df7924cdd8c333db5e1a409ccb2b34e2c3c8c7fdd3fd8"
    "d012cbf382aaa85e83a12f235a2d147d035b7b28b34b6f57949f322482a7d4d3b15045c420"
    "d5addc7f0e69b4dc1cba58b01d872480b06a260d827d891b13c4c5ca50c748de3c771be61e"
    "9aa170165cb01f4bf5da27a7791d3ad3f6267b4cb4e61b28fa1708418d932dfc4161880c5d"
    "3b17a9663a9061fa8f1804315850fe4e7306c882b38227e867f80872cdc1944d472615ea49"
    "00ef7d270b881d4130f56c5cc980d92a47ada6657eb6f37a385d2d8cc993e1442eb0528185"
    "3636991e34aadc68954d04e7adef76bf880f059b0cbb55d915a4b123e2f1339a073cbfbc40"
    "9beff6400ae096d5ae18ec42cffad5b4980fa35bf03413adb5d7e6876ac355d1c9ed70ca2b"
    "973954d12b3cdd76ac6835db96003ed8c4e288b71fd77dbaa7635720e12ae0a317de808c66"
    "4e317f55275791f3245ca4fe5d4d41077fc150a6e403d5a208e46eadbe8f2cfb8af472f4a0"
    "ceac015219478e6b86c958cf86525b7485c1734c7ef00e90683fff5dbd0a7d413a85502102"
    "6a1b32013a4616cbcd3700acbc705be3efba625c69a025267bce9d135e3f5b5cc8c4395640"
    "7e84b6663103e29c242035551ae797f56c6374be0c798c0cf398f1ed";
const absl::string_view kMlDsa65PrivateSeedBytes =
    "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c";

// Taken from
// https://boringssl.googlesource.com/boringssl/+/refs/heads/main/crypto/mldsa/mldsa_nist_keygen_87_tests.txt
const absl::string_view kMlDsa87PublicKeyBytes =
    "862a80dc82eff6cea6a8964febdb42d41a33e2fcefbb5042bca0c90603373281443878eb41"
    "67a46b29b8b97a1c29c83895c7706c95ed7df28407054f8c682c21122d5ee680b3d2c481b9"
    "ca60913af0e92d76584a7a8e4642655f447ce9247b0b41e207139203e7a5f8d5821fbd59d8"
    "65fc91e30fe3ddc54ef5dbd11e4097277a8a2a6e612c41db13e10913d88c18e5359039f8a1"
    "2a86bf37036879f03c2c37110ce128c7a5bd95b99310b5907395f7fbcab8171f22a944b0a7"
    "b52e3e55f5142e5b0a4cd6b3a603597fb1b38396039909568cbb2ca3f867a47309bddd2f3b"
    "0b252d88fa1d19bc5f4bc86e497286b53af4005dcfbab35be1433ffc68fb12ec13a46ee1f7"
    "ca09f543e063a151f3a64f02ca7e838c07835a3ca18a8d50b6a17e36d4cec80a99e3871e2d"
    "af437435611e4095a52ee0e2546b20ed00a590baa058c367771839359c7bdfc75f1db5f661"
    "da87cbe02441f0ef8c85d6ef5032a33995ff9163c6dbd22d69eb4f35b373a0689ab354f977"
    "39c0e7ad9a06facf3c10267870e5788cf70a3f61e9c0e8d054db9864f20e778ee65d417a17"
    "5b6cc5c0a2e4fd70e5583d09b14d93c364eccf357feca398bfb84e3b50d5c98a678a8b2e71"
    "8c836a92c01db091a855f0206d08f3cb233f984ec459f2a36fd4aa4dfe9665c97344cb4dab"
    "b2323a2ffc5690a29bf628295cec833c298640305798c3c1528bf59083309629e1f0845a61"
    "a22a3aa529a5fa38197e58e8ec57c1c5123578f121f2256d67f6068a2bfaa658d731313e45"
    "2638c8f14316763ef305d4e7547af06e2991628fb71003ad77f36f4a1f7a3a166bd1959b87"
    "d17284cc088a5bca8dc518052e799b89d54b953495a5c691f1e4c9ae443e6301f2d0adaef1"
    "83a0f960ad863a3202d64fcc0a318c270033d04142e41fe8d49fb33b8aa1ee71a6ac80e0be"
    "f6c1c71026c18238bf86f6a9815af6030fd52d2446c93e9713f5693d912e427376530beec1"
    "a92e39952c22d6cee8dc74584e7d062fdaff28b5f68a3ccfc29f6fe8385a3e7ef863148d70"
    "b4f8c2adc3a2c32ff685487f48c6e2783d82b95496b42033717cccc1f42e93ce59f2c69942"
    "320191021ef7f9da7df8a2968c15a149e19cf6f293521b25d0088f2ad62df8a6c0eb7c799e"
    "c84dcec1b4ad617a8c35d01f14687a9299db223165ac238d35562793de5ce005483c7e676f"
    "9b178d92ed63e38ceb1fcfbb156897be49789b882ab532bf160d5c0f2d4390ca3299348097"
    "73ce0f03e80998c1feca771eb4bebc22bc9ecbcf0722ee99eb5bc888511e513ed0bba566ac"
    "931cc93c4990595793221ed1aa552059321932603e072d2bcff47a7de572013a8e0f7d32ac"
    "87182dabf6235bdf88a1326d85b9f025f6c191d092d7794b8f5c207511e18d8d01cad19a3f"
    "63f6ab82dc36a3da51653b01b36a946049b369479a1f50927039bbe24be6fd06e212bf9602"
    "51e67404a93b1caf5d9b343630dee7fd872ef6e4d1cc1c65a044c0e91bd98fbcec36b6e570"
    "a47dbb7a0aa3e9a586f8d12876fe24fa5a8fc97af5adf61a0efd0da5f53eba6168968b94c4"
    "08a998819289b19b96032ef643df3b3e69f1f055c31ab172a9d7b92329ff56ab0bdcc60620"
    "d3fcc5d8aa5900e060f459f8423ca028937e72d4210fbffdc08c25ff844e22cc651fe528ae"
    "ea12fc34c48c599b495064b546b720632baf8a29ab532c5d9d85a37fa8e48858ffe70e0f66"
    "d7e7078fa02f02b312601f40c73bea8aaaf75729df50bea269a1566fb133127f7e154eb703"
    "fd70b069e9b1d7094d17a29f76d42006ffd47f8747ef1c416cb6b503c93dbccf77c8717f20"
    "eaa5e196c4c718cdad8a39ae052f0e1f14cb64e2803491d2dcca8bd0a1e29e2b9e7c6abc8d"
    "6bb201185e50184aef8e264e327703bf5a14ebc11b63e95b84abcf466315729df3ee2ad569"
    "d934a0994702dcfa2feeff868ade0b6a4638434b1232e0eceb6f9af00f654e3d7931a7757f"
    "10e173d82955c8606e3f6027d182e316c0038293ab417484d2236bd6a417e48ba445ca9c10"
    "6d52c3f97deafd3a5ecb719dd64b2345dbb9a5905b0a343daeb5e48c264cbb820e548acee9"
    "eccd9588e97578baf0ddc73deb6380225e68b814f20e57b1c7e75cd85746cc7891018f8318"
    "0be697264d2d085ec7ee72205ee58fd9913ad805a6659c43c547bce51ba58a7e7720ecaae9"
    "b54c3f10000cbfa0e233852b76a31b04fc2b22c4112ad4e17e8a23be92c3a226185f604837"
    "f1c4679a6e1536a12a79a6d48d9bea00482ada463ba1aefd0f8d6dc580f84b370ed0e7f9cd"
    "59feb0a68d80328000c5f9f414b110451df834993a9c283e9a179238839169bc21f00a0ccd"
    "36c01d132772d46825598302f44c59bda2b51bf77c6c054c8fb8bf85ccf5a6b058aaeeba64"
    "57dfff8059d0bc00ca01f9599ce90d2537911f169d4fa3ef6fea617de7dea52b11dbc1d4ac"
    "803f6fbc133c83939db1c7c6c2305863232368305d2473a167dfacc8f8dc63d0a1c2787fe6"
    "7cf5323924e70c2f84759f76a7138b4fe6cd4f53da865be7a3055e4c12dd775d85dc76b99a"
    "b38c21343b3dd37f7f9f157d83a3fb171fe29f863fbb36944fb93b0a9ce23edf7370ca3327"
    "fa473b5481266ec0d404380e6cbe800637ab0c8cd9f9b73efda41e1a7b0873ba314b95762e"
    "c3debc9b549ac9901d5c5448779647da29de32f7347d2167226c02063cffde1921ba509f91"
    "bd92ff9e1116e42cdf7acd301b836265d98b0d010b3bfb9a691332e359a804d288edf856d1"
    "4de4116fcc9fe55eba7d04f33cf4a1653adcf1b7d2df562d7c69ed0e493c83956b235862dc"
    "1299b7cb8f8e722fbf2c5cffffc0bdd8cf63faa120802e5d4ab6ecca571cd5435fd3f0975e"
    "6f88b50b0839bb757c139fbf537363332872a90708e7bb86d3e9f98653e0a8730f0ae22288"
    "a128cb9e1cf1c821fa4ab5a4ee2a9b5a4a08b05cf76a8cf7130f56f40947be6bc40772d277"
    "a6da37e729cce932f9acda324cea95959519b5c124c3401d3a8b1d2badc3d287b4e25e503c"
    "36b1947f945b4f6e60ad2fe906396b85a32744de4c9621a429d6fdf0a43d8f957a5f8df50c"
    "66a0dea7ef3ef650810fc809524cc03bb8e9c2b372d0a63b821953a8866608df5b2d3324a6"
    "2343646ff84d92819faa910e38ff75fcf565f21058af46becc71fce43a28f3752d4552be3e"
    "fa9ee356f236b41ea689b9bf9acf8e1f8dc8b753a6b522457aded997ed80d5bb6e0e729ca3"
    "6dc2756b13c53f105d2a004e785a19425b1ec855c9dd2a3f54025b7a526a25dc11c10928e4"
    "86596ef41fd023d5d8a02118099c95f4a8b5f35904cd94a1f1d9432004a40d2328aafba4a8"
    "079ad518b1edc23bde45c1d5b0ac6d6ef86bb0a94e61ecab194a7cd14947693c564b495f64"
    "a6bf4579c4f083e42bdd66042e2c0a1a3676fb75c57d7140ad9cd155c35a7ac70e26ecc52a"
    "d5a41883e751af6326bb23eb5b90484d6c60bf619678d8c85a690f0aeb24302f927518c392"
    "ca38cf894d35d2bb721c9b7951fe26f5cf2d5890b0547b472a6ce5eda12ccef18e19e6e1f9"
    "ca36eccfc8c2ae3a2101d573df119231f3d5352b9794eeab14507a20447961c9025f53457d"
    "6e801f6e1bc34393d062f35e43d2134db0e08aa26bc1ae7d29da240c7d68610ad7882ffb2b"
    "5035";
const absl::string_view kMlDsa87PrivateSeedBytes =
    "19e9e5efe0c1549ddb1d72213636d16fe2faeb2428257004ae464094ca536a66";

struct TestCase {
  JwtMlDsaParameters::KidStrategy kid_strategy;
  JwtMlDsaParameters::Algorithm algorithm;
  absl::optional<std::string> custom_kid;
  absl::optional<int> id_requirement;
  std::string public_key_bytes;
  std::string private_key_bytes;
};

using JwtMlDsaSignerVerifierTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtMlDsaSignerVerifierTests, JwtMlDsaSignerVerifierTest,
    Values(TestCase{JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                    JwtMlDsaParameters::Algorithm::kMlDsa44,
                    /*custom_kid=*/std::nullopt, /*id_requirement=*/123,
                    test::HexDecodeOrDie(kMlDsa44PublicKeyBytes),
                    test::HexDecodeOrDie(kMlDsa44PrivateSeedBytes)},
           TestCase{JwtMlDsaParameters::KidStrategy::kCustom,
                    JwtMlDsaParameters::Algorithm::kMlDsa65,
                    /*custom_kid=*/"custom_kid",
                    /*id_requirement=*/std::nullopt,
                    test::HexDecodeOrDie(kMlDsa65PublicKeyBytes),
                    test::HexDecodeOrDie(kMlDsa65PrivateSeedBytes)},
           TestCase{JwtMlDsaParameters::KidStrategy::kIgnored,
                    JwtMlDsaParameters::Algorithm::kMlDsa87,
                    /*custom_kid=*/std::nullopt,
                    /*id_requirement=*/std::nullopt,
                    test::HexDecodeOrDie(kMlDsa87PublicKeyBytes),
                    test::HexDecodeOrDie(kMlDsa87PrivateSeedBytes)}));

TEST_P(JwtMlDsaSignerVerifierTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  JwtMlDsaPublicKey::Builder builder =
      JwtMlDsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicKeyBytes(test_case.public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  if (test_case.custom_kid.has_value()) {
    builder.SetCustomKid(*test_case.custom_kid);
  }
  absl::StatusOr<JwtMlDsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed = RestrictedData(test_case.private_key_bytes,
                                               InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtMlDsaPrivateKey> private_key = JwtMlDsaPrivateKey::Create(
      *public_key, private_seed, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> signer =
      NewJwtMlDsaSignInternal(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<JwtPublicKeyVerifyInternal>> verifier =
      NewJwtMlDsaVerifyInternal(*public_key);
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<RawJwt> raw_jwt =
      RawJwtBuilder().SetIssuer("issuer").WithoutExpiration().Build();
  ASSERT_THAT(raw_jwt, IsOk());

  absl::StatusOr<JwtValidator> validator = JwtValidatorBuilder()
                                               .ExpectIssuer("issuer")
                                               .AllowMissingExpiration()
                                               .Build();
  ASSERT_THAT(validator, IsOk());

  absl::optional<std::string> kid = std::nullopt;
  if (parameters->GetKidStrategy() ==
      JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId) {
    kid = public_key->GetKid();
  }
  absl::StatusOr<std::string> compact =
      (*signer)->SignAndEncodeWithKid(*raw_jwt, kid);
  ASSERT_THAT(compact, IsOk());
  EXPECT_THAT((*verifier)->VerifyAndDecodeWithKid(*compact, *validator, kid),
              IsOk());
}

}  // namespace
}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
