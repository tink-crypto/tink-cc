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
               "7406a6b5774a383dff42d8f99e46a59b6574f88420b925b689da6d8958"
               "2d9ea707f8fe3dc4e91054df52ee6c28fcf61f6c433ae2a59a93077ae1"
               "26c8d76d4a0c7a5e89da3f9bb8ebae841bc6c1e95655b33100ea77a943"
               "7299a80536c4b22c7f46f6d0f507b5394be5494d4d1e2e66ca09e13717"
               "df3d40ec4fa7e85c13b30263779424e8e503ae6a084c7e6c41b802613d"
               "5082e666a01202e84d41be2cb6a61fe3137ee16d123b3a62ea22a27b8a"
               "bf1057da58897ee1ea9a7f3408018d9ef6f1ec42ae68e8071bbdfbe722"
               "f463943f54530467b7a1e0b57e79c24097495fa09334200c921764aa69"
               "7e8ec982cb9b6e3f4fc4948aeb9dc2aa5231c54b5df511476013a778e9"
               "b6002f2327680f55502c4fc7ae5ec363155f9a6557e0568c07e0e7f267"
               "9234293f773950d4b967d64380eb9a39773229b46df8beea3926ea61ee"
               "9c68b7ca7fc8f7422c544d9aa2e5cbb3273e970b165b4c10714ee6b783"
               "51543b5907f8976b328dcbe35f99ee303d8d34b56c4aa95b7fe2b9472d"
               "8e7d23d881958b5a6e2e04374347716f9038ec18991b1be04cb31cb5a4"
               "0a64860b2496d66e7f1cc31df95e0c52f7596ff10fa25e985b54d6d6ec"
               "1dafa5b26ca3d8b1aa76ef3d4f170fa59c4fa770c0c6604618e59fa202"
               "11a7c73a4d95b5ce3d1da68e8b0b924b98cb5c1be78263eb4c1c5ceec2"
               "f928e4e73b22eaee1f516dbccb8c2c54f48b11f86b36a10ce3e4b7c6c4"
               "9bc8dc4abce291ef77bc404f85e5c70757a3e8bb82d3ca26a273bcf415"
               "d9ab96362d5eaebae9d1fa34c1a5d09f7a77d3f82aa5cb9aa9d8dc2fa1"
               "372da2ea8df483b8b64b58e72da7793b5bb2396bb6b359f518e11a14f5"
               "b8971f4ea24dfc0d603a1fe231f29bcf0c2dbe4889c67645100067bba4"
               "dcbf20ee307238a2e58e38d6df028889aa31aa7e35b7e28df13b290924"
               "97678512146013a778e9b6002f2327680f55502c4fc7ae5ec363155f9a"
               "6557e0568c07e0e784a8607149c445c5c36ea6d1cf7b194a81e3a6c117"
               "d91d17d057774ff0ea1279dc8b7f8fba3a22da7aa0f0ba35f4dfa1d82e"
               "a7945d8b762551a37c35d9471f462d54d58ce88126b866c152e043187c"
               "336cbff83e74f3daec1ce8cae3ef8e18b8c5e9fcf096350f585d5ce9f2"
               "68f70092c4b7ec3b30e01c51da3341b52a5501869fa69b6118d36154e1"
               "ab8b7050518ff47b8e1f574218683e35a1215bb4b931be34200c921764"
               "aa697e8ec982cb9b6e3f4fc4948aeb9dc2aa5231c54b5df51147a77a46"
               "fa31518f8e0bb8776602377a94ef550f24213d2f9bf2b3b0d778d9b232"
               "7e4d5885c39f1c7d2c3df4740e53a32f6236b2f0a1ea3e9c5658e4d2a7"
               "1d9f8ec36746ef7d3839213e4b7899b6ef9fa982a5c531d0532279b980"
               "9971ec646bb46013a778e9b6002f2327680f55502c4fc7ae5ec363155f"
               "9a6557e0568c07e0e7b576884639912bb9b30c4fa47cfb0e5bfb04d137"
               "78a87b8d0ca5970c79ef539499015c721ae7082f42a53702e5b7e28b12"
               "2709cb463c631e5f84d6b63c7ba395e83ea88ca298f244196fa925c4ef"
               "69d4d4204eb8b83597d2642674e2d36c84f320ee307238a2e58e38d6df"
               "028889aa31aa7e35b7e28df13b2909249767851214a2c26ea6143997db"
               "7015d862d87e07a2754bbbe52f20531c3bf611ae26f041771c1ea354c4"
               "14995f9c5225010619280d0d80c35e98516084931ea41e06d9d4a307f8"
               "976b328dcbe35f99ee303d8d34b56c4aa95b7fe2b9472d8e7d23d88195"
               "8bc36746ef7d3839213e4b7899b6ef9fa982a5c531d0532279b9809971"
               "ec646bb4014bdf7378d3ba11d954f923e32e850b57e79c24097495fa09"
               "334200c921764aa697e8ec982cb9b6e3f4fc4948aeb9dc2aa5231c54b5"
               "df511476013a778e9b6002f2327680f55502c4fc7ae5ec363155f9a655"
               "7e0568c07e0e784a8607149c445c5c36ea6d1cf7b194a81e3a6c117d91d"
               "17d057774ff0ea1279dc8b7f8fba3a22da7aa0f0ba35f4dfa1d82ea794"
               "5d8b762551a37c35d9471f462d54d58ce88126b866c152e043187c336c"
               "bff83e74f3daec1ce8cae3ef8e18b8c5e9fcf096350f585d5ce9f268f7"
               "0092c4b7ec3b30e01c51da3341b52a5501869fa69b6118d36154e1ab8b"
               "7050518ff47b8e1f574218683e35a1215bb4b931be34200c921764a",
               "99df8544d67ea27561a0eb1b2ab10ee3a9f074d2847ea6309831969a4c"
               "0422c5")},
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
