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

#include "tink/jwt/internal/testing/jwt_ml_dsa_test_vectors.h"

#include <utility>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/util/test_util.h"

namespace crypto::tink::jwt_internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

JwtMlDsaTestVector MakeJwtMlDsaTestVector(
    JwtMlDsaParameters::Algorithm algorithm, absl::string_view public_key_hex,
    absl::string_view private_seed_hex) {
  return JwtMlDsaTestVector{
      algorithm,
      HexDecodeOrDie(public_key_hex),
      HexDecodeOrDie(private_seed_hex),
  };
}

using JwtMlDsaTestVectorMap =
    absl::flat_hash_map<JwtMlDsaParameters::Algorithm, JwtMlDsaTestVector>;

const JwtMlDsaTestVectorMap& CreateJwtMlDsaTestVectorsMap() {
  static const absl::NoDestructor<JwtMlDsaTestVectorMap> test_vectors(
      JwtMlDsaTestVectorMap{
          {JwtMlDsaParameters::Algorithm::kMlDsa44,
           MakeJwtMlDsaTestVector(
               JwtMlDsaParameters::Algorithm::kMlDsa44,
               "b845fa2881407a59183071629b08223128116014fb58ff6bb4c8c9fe19"
               "cf5b0bd77b16648a344ffe486bc3e3cb5fab9abc4cc2f1c34901692bec"
               "5d290d815a6cdf7e9710a3388247a7e0371615507a572c9835e6737bf3"
               "0b92a796fff3a10a730c7b550924eb1fb6d56195f02de6d3746f9f330b"
               "ebe990c90c4d676ad415f4268d2d6b548a8bcdf27fdd467e6749c0f87b"
               "71e85c2797694772bba88d4f1ac06c7c0e91786472cd76353708d6bbc5"
               "c28e9db891c3940e879052d30c8fd10965cbb8ee1bd79b060d37fb8390"
               "98552aabdd3a57ab1c6a82b0911d1cf148654aa5613b07014b21e4a118"
               "2b4a5501671d112f5975fb0c8a2ac45d575dc42f48977ff37fff421db2"
               "7c45e79f8a9472007023df0b64205cd9f57c02ce9d1f61f2ae24f7139f"
               "5641984ee8df783b9ea43e997c6e19d09e062afca56e4f76aaab8f6660"
               "0fc78f6ab4f6785690d185816ee35a939458b60324eefc60e64b11fa0d"
               "20317acb6cb29aa03c775f151672952689fa4f8f838329cb9e6dc9945b"
               "6c7ade4e7b663578f87d3935f2a1522097ad5042a0d990a628510b6103"
               "cb242cd8a3afc1a5ada52331f4df461bc1da51d1d224094e7abed3d87d"
               "98f0d817084780ee80370f397631ecb75d4264b6b5e2e66c0586b5fb74"
               "3516399165837a0fdff7c6134f033bfa69c1b2416965c6e578592f40e2"
               "58cb6dfb29fb8e0f54355b6e24a65f67abae3193d007115cc0b9ff94cb"
               "911a93b1a76c0e7662f5e2b20139e0159ed929cb932d4895f89a02e55c"
               "59df2dbb8f6e5dd7d5b1f3cec37b4a9166b381c5440e23e67368cde0a2"
               "9d59aa05a3c9be24a4dc8dd75be30e82bc635d36aac66de880c6701a98"
               "7d7e05f0f2ff287828bec30595089d8ab9aa390ed719caa6e576cdbbe9"
               "b184a322e5e2dabb69c23cc696d54fc32ff57001b6b64e2a837f3062d8"
               "5aeb50b3510f7edfc34df38e083d4d9b94ffab0de15d73d9af30b9f31c"
               "c4f41c9c24f2d618b2a7c3c4bdfb745d52d3eb54589c8bda8ac05dad14"
               "ec744505575a0988eec651c1715439fdfb29923380a43c1a66a86c982a"
               "841f11820a6a0e1e2f2fff5108ecae51a6aabc9b949226d228ff84c4e5"
               "e5d63114d80359c4931e612dced1838b7d066ac9182cecfa223a21a4c8"
               "e155aefa780373bcc15098aee40c033af22f8e7c67a0d2526da7475e83"
               "0308c04aed9d32bccc72e719ee70a8d13f09ac11e26ea237d5cc8f98b5"
               "ae0e54f933bd0507942ed900d056fd32f8e6e81777912fd482746029b7"
               "1cce3ba69b8fc2d03eb441027c387bc2f95031a0ae7052215eb24b9ea8"
               "fb0a961b0f80bfa80d0d6257c1c22b508c5d31b97fcdfe1d1766e8a9c8"
               "771932dd598adb7e717743f45fc571f21e4a516249f81d747f15329790"
               "f0f70a0b8e461a4edf50504af03f30ddf8a8818e38761e1681d6ddef0b"
               "1dd326b2ec228ce48570f285b49d29d7c2ef37866d5446df82b8e43b34"
               "cb248962a21a9a3946159740f8aee8e6a16a4eb2b42d143fe2612e05ef"
               "4b5e646d813248444556a2a8bf92ce10badecb6b8a40b080dd42d53346"
               "fefcc4b9b40b1e4998991ec753c95aa2f2a506f311e710b0f1d36c1dca"
               "6644ee6d1d4ae9cea5666ef4b3e888dbdbb95a77ecfe1e8b477de7cb07"
               "639d682d53020ec14ea6c7dd7e715389d10938429fab8a068a1466a4cd"
               "891359f8074e0f5a142add731b87878d985e4fa6ecb3b73d2985534182"
               "73e9503aa84092c080e5f2902f90f5c59944d24ca0271d11d0d6734606"
               "d039550a37fca2b735850e63f540f2f06b79144b5c4ed2c700bb51c33d"
               "265b3d037389c99efd597642d829db1eb58643cfcd07f4dec60b8f727d"
               "97bd7c4b59bda1",
               "d71361c000f9a7bc99dfb425bcb6bb27c32c36ab444ff3708b2d93b4e6"
               "6d5b5b")},
          {JwtMlDsaParameters::Algorithm::kMlDsa65,
           MakeJwtMlDsaTestVector(
               JwtMlDsaParameters::Algorithm::kMlDsa65,
               "d2fd03f3a1b7f635af9f34d580a98f524c735bd5ba2355dc6e035bd217"
               "65580cbb111923f194a7cc8a7bb2ebc5c0e71aa637cc800e6103b850a5"
               "39b2a39e1b6d713e5db8314c9ae1f8bf8a38f06afb9d73b161b0ffe3a4"
               "891706ae26d54ffb496df8dc0f1983509500c9abbd28e59b3fcdabbdad"
               "abd45ec31499378bde849e7c1f19b7044d67e05106d7136d95380d5605"
               "d4465d877557065df0a75d3c28542f40feed42ec7e280637b083d988bc"
               "a5f6394e02396c4676184fb63318dafaf5bbdde00e308fe84019c2340a"
               "3f3e1c0865624970711283356ae14bd6b94d1c9ae188de1a8a2ca824a8"
               "eae2fe6afb38d83a2d99996ab21fe3e84c0be6b6da08879b677374fa7c"
               "691b13d40fa9d4cc26b2288d5a8c9a43724381004d61b0d57ff400314c"
               "8e30ee796af10f7ee21bf13d08180465abc72eddb080c6a07184e3eedc"
               "47c19aa7f09d1f3309e183a2bd9b0573dde474a81ba4f78d0c523d0c04"
               "f90060fd571a35c037e079c5e210d7390df568f2e2f03ce44420c82f3f"
               "e69eb9b48ee90962d6b0f24440648f71edb241ee6566fc1a64cabf66be"
               "6fecbcb1387c82a7bc202d9e367998e2a291af0cd1570677fe8d63a328"
               "5a2ea6eb29af9dc1aec1c36c4706b12baa20839692f286a6e0321468f7"
               "479345c4d52fbdb2f06725b554b89e2492612681acebc6c7bada922581"
               "8dbc35d64c22c48bff80a730d0716dfac99dfd5b8992611d0c93ee90bd"
               "b260022afe25d913e06effb59cb1f8a60cbfa5ab2f459a16f467e98952"
               "5e0a37ebe56e833fde55db9d1530adcf45846df281e47caa1e0a27efde"
               "2107d354cea0f6a454692f04cd838ebdd46e191e5d9c11839a2c3f488a"
               "4fc7cd265a7b5d32b08cbdbfab9d2ccd76222c8ee37ddcbd2aa063ed86"
               "1473a6454caea377850b1a2b9ddbbcb374fab5b12f351c8e5888872e5c"
               "d1f60a4fae1ff837d192c22beb41ee6fa392fcdf4550ff46b5ce906d01"
               "7ef3077df132300d8bbfa9bb03c75e79e2f04c284ad06a44399649c3e2"
               "a2a8d1efe9b7a4e0c271047ab75908bff7df9e30eca547745bae23a86f"
               "f9a8b58c2538b88b866401076902dc5f0bd761687b49eafe36d350cbed"
               "fdd36c121cf23786bfcf7e47076496eab6bbda774049c2ebabe2de99c4"
               "c24f2db73684015b373977496760cf9ac23d8b623133db2de10d73fa6a"
               "d1c6dac8434f28c6e251ce7293cff3f3b61efcb5a435123670f29846a1"
               "3df3ee712604461f1bab8f4ebc836de058978ae734396a98081b35cc98"
               "188a86949c99270d4709854c5b35b17f48a373134c814cc8a0f3e2fa80"
               "7f2a918530907864778282d75e03a41b2504eed816a417a3ac6ba16080"
               "c39b7310192002a728f7f20395009a9e16767ce1971f5de7d229a50613"
               "369e4382045a8e81901f4dba8102f3d413fe35b326a874f233b719a713"
               "7600d35d33aeb6b7259624083aa968730c8f78292ad28f14eeabe66083"
               "5984fe69ef23dec8c327c0eb0b882d587e1ec433da85c9fd1e0a34994d"
               "ea240c854452d18c30f496e49ec904b602e0f5062edcda03280a53b431"
               "3574cc2c0d5471bc9613bdfd6641f5bd127bab5b5eb3d499a331140482"
               "20e819f8ee12ca922c8f17d9c9f51ad5bd6883b10e6aa2483ba49dc547"
               "da7686151344f4e9099b38e430b5226b059832cf03db48fb02dba4e615"
               "93dc4576360491890e53ec0e6ac73cf32b25d823b38456e286505a541e"
               "5aeee96b1914f5f76687ce2b0160227abed77993594bcd831366206d75"
               "714082f1c46f1f4439ac81a57af31c81c555307a070ffa94e0479b784b"
               "bd88a60cd4c7cfd94e6afe02f6b21f72af0dcd6609d40c965c14e5f238"
               "9183e53de930f7de1d44215cf49144844e8b87f78a7f132aefe22be80b"
               "4e3a05ee3a68ccf609ef44047402e4493046e6f9c767ff8a75e28b3ce0"
               "77fde7e7eed313b5bf7e460127ca8182e9bc794c0dfa730fb920080575"
               "a751b5caec85a109b4422ba266743f0d032bda8f1ca6248cdb917530df"
               "1302a5f8c18dc642d52478c98c12a3f16ef2b62b4f59ea1bb58de7b65b"
               "3c7153ce6da5e4950746f80e087a0e3586d097791bf36def865d68591d"
               "39d0903773eea962147f34704138b54df7924cdd8c333db5e1a409ccb2"
               "b34e2c3c8c7fdd3fd8d012cbf382aaa85e83a12f235a2d147d035b7b28"
               "b34b6f57949f322482a7d4d3b15045c420d5addc7f0e69b4dc1cba58b0"
               "1d872480b06a260d827d891b13c4c5ca50c748de3c771be61e9aa17016"
               "5cb01f4bf5da27a7791d3ad3f6267b4cb4e61b28fa1708418d932dfc41"
               "61880c5d3b17a9663a9061fa8f1804315850fe4e7306c882b38227e867"
               "f80872cdc1944d472615ea4900ef7d270b881d4130f56c5cc980d92a47"
               "ada6657eb6f37a385d2d8cc993e1442eb05281853636991e34aadc6895"
               "4d04e7adef76bf880f059b0cbb55d915a4b123e2f1339a073cbfbc409b"
               "eff6400ae096d5ae18ec42cffad5b4980fa35bf03413adb5d7e6876ac3"
               "55d1c9ed70ca2b973954d12b3cdd76ac6835db96003ed8c4e288b71fd7"
               "7dbaa7635720e12ae0a317de808c664e317f55275791f3245ca4fe5d4d"
               "41077fc150a6e403d5a208e46eadbe8f2cfb8af472f4a0ceac01521947"
               "8e6b86c958cf86525b7485c1734c7ef00e90683fff5dbd0a7d413a8550"
               "21026a1b32013a4616cbcd3700acbc705be3efba625c69a025267bce9d"
               "135e3f5b5cc8c43956407e84b6663103e29c242035551ae797f56c6374"
               "be0c798c0cf398f1ed",
               "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d8"
               "5c225c")},
          {JwtMlDsaParameters::Algorithm::kMlDsa87,
           MakeJwtMlDsaTestVector(
               JwtMlDsaParameters::Algorithm::kMlDsa87,
               "862a80dc82eff6cea6a8964febdb42d41a33e2fcefbb5042bca0c906033732"
               "81443878eb4167a46b29b8b97a1c29c83895c7706c95ed7df28407054f8c68"
               "2c21122d5ee680b3d2c481b9ca60913af0e92d76584a7a8e4642655f447ce9"
               "247b0b41e207139203e7a5f8d5821fbd59d865fc91e30fe3ddc54ef5dbd11e"
               "4097277a8a2a6e612c41db13e10913d88c18e5359039f8a12a86bf37036879"
               "f03c2c37110ce128c7a5bd95b99310b5907395f7fbcab8171f22a944b0a7b5"
               "2e3e55f5142e5b0a4cd6b3a603597fb1b38396039909568cbb2ca3f867a473"
               "09bddd2f3b0b252d88fa1d19bc5f4bc86e497286b53af4005dcfbab35be143"
               "3ffc68fb12ec13a46ee1f7ca09f543e063a151f3a64f02ca7e838c07835a3c"
               "a18a8d50b6a17e36d4cec80a99e3871e2daf437435611e4095a52ee0e2546b"
               "20ed00a590baa058c367771839359c7bdfc75f1db5f661da87cbe02441f0ef"
               "8c85d6ef5032a33995ff9163c6dbd22d69eb4f35b373a0689ab354f97739c0"
               "e7ad9a06facf3c10267870e5788cf70a3f61e9c0e8d054db9864f20e778ee6"
               "5d417a175b6cc5c0a2e4fd70e5583d09b14d93c364eccf357feca398bfb84e"
               "3b50d5c98a678a8b2e718c836a92c01db091a855f0206d08f3cb233f984ec4"
               "59f2a36fd4aa4dfe9665c97344cb4dabb2323a2ffc5690a29bf628295cec83"
               "3c298640305798c3c1528bf59083309629e1f0845a61a22a3aa529a5fa3819"
               "7e58e8ec57c1c5123578f121f2256d67f6068a2bfaa658d731313e452638c8"
               "f14316763ef305d4e7547af06e2991628fb71003ad77f36f4a1f7a3a166bd1"
               "959b87d17284cc088a5bca8dc518052e799b89d54b953495a5c691f1e4c9ae"
               "443e6301f2d0adaef183a0f960ad863a3202d64fcc0a318c270033d04142e4"
               "1fe8d49fb33b8aa1ee71a6ac80e0bef6c1c71026c18238bf86f6a9815af603"
               "0fd52d2446c93e9713f5693d912e427376530beec1a92e39952c22d6cee8dc"
               "74584e7d062fdaff28b5f68a3ccfc29f6fe8385a3e7ef863148d70b4f8c2ad"
               "c3a2c32ff685487f48c6e2783d82b95496b42033717cccc1f42e93ce59f2c6"
               "9942320191021ef7f9da7df8a2968c15a149e19cf6f293521b25d0088f2ad6"
               "2df8a6c0eb7c799ec84dcec1b4ad617a8c35d01f14687a9299db223165ac23"
               "8d35562793de5ce005483c7e676f9b178d92ed63e38ceb1fcfbb156897be49"
               "789b882ab532bf160d5c0f2d4390ca329934809773ce0f03e80998c1feca77"
               "1eb4bebc22bc9ecbcf0722ee99eb5bc888511e513ed0bba566ac931cc93c49"
               "90595793221ed1aa552059321932603e072d2bcff47a7de572013a8e0f7d32"
               "ac87182dabf6235bdf88a1326d85b9f025f6c191d092d7794b8f5c207511e1"
               "8d8d01cad19a3f63f6ab82dc36a3da51653b01b36a946049b369479a1f5092"
               "7039bbe24be6fd06e212bf960251e67404a93b1caf5d9b343630dee7fd872e"
               "f6e4d1cc1c65a044c0e91bd98fbcec36b6e570a47dbb7a0aa3e9a586f8d128"
               "76fe24fa5a8fc97af5adf61a0efd0da5f53eba6168968b94c408a998819289"
               "b19b96032ef643df3b3e69f1f055c31ab172a9d7b92329ff56ab0bdcc60620"
               "d3fcc5d8aa5900e060f459f8423ca028937e72d4210fbffdc08c25ff844e22"
               "cc651fe528aeea12fc34c48c599b495064b546b720632baf8a29ab532c5d9d"
               "85a37fa8e48858ffe70e0f66d7e7078fa02f02b312601f40c73bea8aaaf757"
               "29df50bea269a1566fb133127f7e154eb703fd70b069e9b1d7094d17a29f76"
               "d42006ffd47f8747ef1c416cb6b503c93dbccf77c8717f20eaa5e196c4c718"
               "cdad8a39ae052f0e1f14cb64e2803491d2dcca8bd0a1e29e2b9e7c6abc8d6b"
               "b201185e50184aef8e264e327703bf5a14ebc11b63e95b84abcf466315729d"
               "f3ee2ad569d934a0994702dcfa2feeff868ade0b6a4638434b1232e0eceb6f"
               "9af00f654e3d7931a7757f10e173d82955c8606e3f6027d182e316c0038293"
               "ab417484d2236bd6a417e48ba445ca9c106d52c3f97deafd3a5ecb719dd64b"
               "2345dbb9a5905b0a343daeb5e48c264cbb820e548acee9eccd9588e97578ba"
               "f0ddc73deb6380225e68b814f20e57b1c7e75cd85746cc7891018f83180be6"
               "97264d2d085ec7ee72205ee58fd9913ad805a6659c43c547bce51ba58a7e77"
               "20ecaae9b54c3f10000cbfa0e233852b76a31b04fc2b22c4112ad4e17e8a23"
               "be92c3a226185f604837f1c4679a6e1536a12a79a6d48d9bea00482ada463b"
               "a1aefd0f8d6dc580f84b370ed0e7f9cd59feb0a68d80328000c5f9f414b110"
               "451df834993a9c283e9a179238839169bc21f00a0ccd36c01d132772d46825"
               "598302f44c59bda2b51bf77c6c054c8fb8bf85ccf5a6b058aaeeba6457dfff"
               "8059d0bc00ca01f9599ce90d2537911f169d4fa3ef6fea617de7dea52b11db"
               "c1d4ac803f6fbc133c83939db1c7c6c2305863232368305d2473a167dfacc8"
               "f8dc63d0a1c2787fe67cf5323924e70c2f84759f76a7138b4fe6cd4f53da86"
               "5be7a3055e4c12dd775d85dc76b99ab38c21343b3dd37f7f9f157d83a3fb17"
               "1fe29f863fbb36944fb93b0a9ce23edf7370ca3327fa473b5481266ec0d404"
               "380e6cbe800637ab0c8cd9f9b73efda41e1a7b0873ba314b95762ec3debc9b"
               "549ac9901d5c5448779647da29de32f7347d2167226c02063cffde1921ba50"
               "9f91bd92ff9e1116e42cdf7acd301b836265d98b0d010b3bfb9a691332e359"
               "a804d288edf856d14de4116fcc9fe55eba7d04f33cf4a1653adcf1b7d2df56"
               "2d7c69ed0e493c83956b235862dc1299b7cb8f8e722fbf2c5cffffc0bdd8cf"
               "63faa120802e5d4ab6ecca571cd5435fd3f0975e6f88b50b0839bb757c139f"
               "bf537363332872a90708e7bb86d3e9f98653e0a8730f0ae22288a128cb9e1c"
               "f1c821fa4ab5a4ee2a9b5a4a08b05cf76a8cf7130f56f40947be6bc40772d2"
               "77a6da37e729cce932f9acda324cea95959519b5c124c3401d3a8b1d2badc3"
               "d287b4e25e503c36b1947f945b4f6e60ad2fe906396b85a32744de4c9621a4"
               "29d6fdf0a43d8f957a5f8df50c66a0dea7ef3ef650810fc809524cc03bb8e9"
               "c2b372d0a63b821953a8866608df5b2d3324a62343646ff84d92819faa910e"
               "38ff75fcf565f21058af46becc71fce43a28f3752d4552be3efa9ee356f236"
               "b41ea689b9bf9acf8e1f8dc8b753a6b522457aded997ed80d5bb6e0e729ca3"
               "6dc2756b13c53f105d2a004e785a19425b1ec855c9dd2a3f54025b7a526a25"
               "dc11c10928e486596ef41fd023d5d8a02118099c95f4a8b5f35904cd94a1f1"
               "d9432004a40d2328aafba4a8079ad518b1edc23bde45c1d5b0ac6d6ef86bb0"
               "a94e61ecab194a7cd14947693c564b495f64a6bf4579c4f083e42bdd66042e"
               "2c0a1a3676fb75c57d7140ad9cd155c35a7ac70e26ecc52ad5a41883e751af"
               "6326bb23eb5b90484d6c60bf619678d8c85a690f0aeb24302f927518c392ca"
               "38cf894d35d2bb721c9b7951fe26f5cf2d5890b0547b472a6ce5eda12ccef1"
               "8e19e6e1f9ca36eccfc8c2ae3a2101d573df119231f3d5352b9794eeab1450"
               "7a20447961c9025f53457d6e801f6e1bc34393d062f35e43d2134db0e08aa2"
               "6bc1ae7d29da240c7d68610ad7882ffb2b5035",
               "19e9e5efe0c1549ddb1d72213636d16fe2faeb2428257004ae464094ca536a"
               "66")},
      });
  return *test_vectors;
}

}  // namespace

const JwtMlDsaTestVector& CreateJwtMlDsa44TestVector() {
  return GetJwtMlDsaTestVector(JwtMlDsaParameters::Algorithm::kMlDsa44);
}

const JwtMlDsaTestVector& CreateJwtMlDsa65TestVector() {
  return GetJwtMlDsaTestVector(JwtMlDsaParameters::Algorithm::kMlDsa65);
}

const JwtMlDsaTestVector& CreateJwtMlDsa87TestVector() {
  return GetJwtMlDsaTestVector(JwtMlDsaParameters::Algorithm::kMlDsa87);
}

const JwtMlDsaTestVector& GetJwtMlDsaTestVector(
    JwtMlDsaParameters::Algorithm algorithm) {
  const JwtMlDsaTestVectorMap& map = CreateJwtMlDsaTestVectorsMap();
  auto it = map.find(algorithm);
  ABSL_CHECK(it != map.end())
      << "No JWT ML-DSA test vector found for algorithm.";
  return it->second;
}

}  // namespace crypto::tink::jwt_internal
