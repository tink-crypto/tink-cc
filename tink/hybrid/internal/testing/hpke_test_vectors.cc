// Copyright 2024 Google LLC
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

#include "tink/hybrid/internal/testing/hpke_test_vectors.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mlkem_util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto::tink::internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::util::SecretDataFromStringView;

// P-256 public point and private key from RFC 6979, Appendix A.2.5.
constexpr absl::string_view kP256PublicKeyHex =
    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
constexpr absl::string_view kP256PrivateKeyHex =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

// P-384 public point and private key from RFC 6979, Appendix A.2.6.
constexpr absl::string_view kP384PublicKeyHex =
    "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea"
    "9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9"
    "f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720";
constexpr absl::string_view kP384PrivateKeyHex =
    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e"
    "4c70a825f872c9ea60d2edf5";

// P-521 public point and private key from RFC 6979, Appendix A.2.7.
constexpr absl::string_view kP521PublicKeyHex =
    "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d4"
    "6e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962"
    "cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828"
    "008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5";
constexpr absl::string_view kP521PrivateKeyHex =
    "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb"
    "32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538";

// X25519 public and private key from RFC 7748, Section 6.1.
constexpr absl::string_view kX25519PublicKeyHex =
    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431";
constexpr absl::string_view kX25519PrivateKeyHex =
    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736";

// X-Wing public and private key from RFC 9180 /
// draft-connolly-cfrg-xwing-kem-09.
constexpr absl::string_view kXWingPublicKeyHex =
    "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d"
    "a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b"
    "2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534"
    "01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361"
    "0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c"
    "1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06"
    "3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae"
    "a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e"
    "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40"
    "b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c"
    "1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362"
    "543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564"
    "955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e"
    "d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af"
    "829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519"
    "317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4"
    "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be"
    "3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587"
    "ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584"
    "fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c"
    "8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09"
    "0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95"
    "2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406"
    "5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5"
    "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173"
    "46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573"
    "cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369"
    "8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c"
    "1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44"
    "d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96"
    "9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611"
    "d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734"
    "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06"
    "eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534";
constexpr absl::string_view kXWingPrivateKeyHex =
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";

// ML-KEM shared seed and public keys from NIST FIPS 203.
constexpr absl::string_view kMlKemPrivateKeyHex =
    "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79"
    "d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f";

constexpr absl::string_view kMlKem768PublicKeyHex =
    "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913"
    "a8d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35f"
    "baeb73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e"
    "535b260aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a517"
    "16aa01660c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb74"
    "8ee391e98934a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063"
    "364646d6d699db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b0"
    "2a4c03d09b44815c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a3"
    "03402830ec01db7b2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253"
    "c8415bd7825f02bb229369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391"
    "f989ade314729c331fa04c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a"
    "612948a3483c7f1b9a258000e30196944a403627609c76c7ea6b5de01764d24379117b9e"
    "a29848dc555c454bceae1ba5cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151"
    "a19c6cd7938454372465e4c5ec29245acb3db5379de3dabfa629a7c04a8353a8530c95ac"
    "b732bb4bb81932bb2ca7a848cd366801444abe23c83b366a87d6a3cf360924c002bae90a"
    "f65c48060b3752f2badf1ab2722072554a5059753594e6a702761fc97684c8c4a7540a6b"
    "07fbc9de87c974aa8809d928c7f4cbbf8045aea5bc667825fd05a521f1a4bf539210c711"
    "3bc37b3e58b0cbfc53c841cbb0371de2e511b989cb7c70c023366d78f9c37ef047f8720b"
    "e1c759a8d96b93f65a94114ffaf60d9a81795e995c71152a4691a5a602a9e1f3599e37c7"
    "68c7bc108994c0669f3adc957d46b4b6256968e290d7892ea85464ee7a750f39c5e3152c"
    "2dfc56d8b0c924ba8a959a68096547f66423c838982a5794b9e1533771331a9a656c2882"
    "8beb9126a60e95e8c5d906832c7710705576b1fb9507269ddaf8c95ce9719b2ca8dd112b"
    "e10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923a86957671d619335be1c4c2c77ce"
    "87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da4d8ee64f68c02189bbb3584baf"
    "f716c85db654048a004333489393a07427cd3e217e6a345f6c2c2b13c27b337271c0b27b"
    "2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796b4b0187004258049a477cd"
    "11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694ca795c4f40e7acc9c5a1"
    "884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a7215aa4a748c15836c38"
    "9137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd1485543229d3748d9b5cd"
    "6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab51bdc4bbfe8308e"
    "663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87ced7aac41c82"
    "888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc61a1a3f736"
    "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028";

constexpr absl::string_view kMlKem1024PublicKeyHex =
    "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c318"
    "3d2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca"
    "0ef488b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745"
    "f2944016ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7"
    "c0e589bfb5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f3197"
    "39f40c4f42b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b6"
    "9438bf991776286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b7"
    "4425c26e4a20dd9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e"
    "7cc28f10344062c10e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39"
    "d5589a50e133389c9b9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b"
    "276656b9d8a4eb71896ff589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c1"
    "2aa6b95e2b0cbe4331bb24a33a270153aa472c47312382ca365c5f35259d025746fc6595"
    "fe636c767510a69c1e8a176b7949958f2697399497a2fc7364a12c8198295239c826cb50"
    "82086077282ed628651fc04c639b438522a9de309b14b086d6e923c551623bd72a733cb0"
    "dabc54a9416a99e72c9fda1cb3fb9ba06b8adb2422d68cadc553c98202a17656478ac044"
    "ef3456378abce9991e0141ba79094fa8f77a300805d2d32ffc62bf0ca4554c330c2bb704"
    "2db35102f68b1a0062583865381c74dd913af70b26cf0923d0c4cb971692222552a8f4b7"
    "88b4afd1341a9df415cf203900f5ccf7f65988949a75580d049639853100854b21f40180"
    "03502bb1ba95f556a5d67c7eb52410eba288a6d0635ca8a4f6d696d0a020c826938d3494"
    "3c3808c79cc007768533216bc1b29da6c812eff3340baa8d2e65344f09bd47894f5a3a41"
    "18715b3c5020679327f9189f7e10856b238bb9b0ab4ca85abf4b21f5c76bccd71850b22e"
    "045928276a0f2e951db0707c6a116dc19113fa762dc5f20bd5d2ab5be71744dc9cbdb51e"
    "a757963aac56a90a0d8023bed1f5cae8a64da047279b353a096a835b0b2b023b6aa04898"
    "9233079aeb467e522fa27a5822921e5c551b4f537536e46f3a6a97e72c3b063104e09a04"
    "0598940d872f6d871f5ef9b4355073b54769e45454e6a0819599408621ab4413b35507b0"
    "df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75161406e71c5ff92451a775"
    "22b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c730c45003aca2bf0f8424"
    "a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f60922ba19de73b1917f185"
    "3273555199a649318b50773345c997460856972acb43fc81ab6321b1c33c2bb5098bd489"
    "d696a0f70679c1213873d08bdad42844927216047205633212310ee9a06cb10016c80550"
    "3c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9c54bc8375784"
    "47aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad41bc680532b"
    "89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc265c0483a6"
    "5ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034733b04"
    "85dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258b4af"
    "71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91cd"
    "6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166"
    "d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446"
    "d345bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376"
    "e5a6747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750"
    "762631c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa72244"
    "61a5cc27405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a4"
    "6d195581d173854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abf"
    "bad10738ad04cc752bc20c394746850e0c4847db";

struct HpkeTestVectorParams {
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  HpkeParameters::Variant variant;
  std::optional<int> id_requirement;
  absl::string_view public_key_hex;
  absl::string_view private_key_hex;
  absl::string_view plaintext_hex;
  absl::string_view context_info_hex;
  absl::string_view ciphertext_hex;
};

HybridTestVector MakeHpkeTestVector(const HpkeTestVectorParams& params) {
  absl::StatusOr<HpkeParameters> hpke_parameters =
      HpkeParameters::Builder()
          .SetKemId(params.kem_id)
          .SetKdfId(params.kdf_id)
          .SetAeadId(params.aead_id)
          .SetVariant(params.variant)
          .Build();
  ABSL_CHECK_OK(hpke_parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *hpke_parameters, HexDecodeOrDie(params.public_key_hex),
      params.id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(HexDecodeOrDie(params.private_key_hex),
                     InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*std::move(private_key)),
      HexDecodeOrDie(params.plaintext_hex),
      HexDecodeOrDie(params.context_info_hex),
      HexDecodeOrDie(params.ciphertext_hex));
}

using HpkeTestVectorMap = absl::flat_hash_map<
    std::tuple<HpkeParameters::KemId, HpkeParameters::KdfId,
               HpkeParameters::AeadId, HpkeParameters::Variant>,
    HybridTestVector>;

const HpkeTestVectorMap& CreateHpkeTestVectorsMap() {
  static const absl::NoDestructor<HpkeTestVectorMap> test_vectors(
      HpkeTestVectorMap{
          // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, NO_PREFIX
          // From RFC 9180, Appendix A.1.1 and Tink Java (HpkeTestUtil.java
          // vector 0).
          {{HpkeParameters::KemId::kDhkemP256HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemP256HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kP256PublicKeyHex,
               /*private_key_hex=*/kP256PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba74234494"
               "b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f"
               "59b069dffc8427cfb7f277ed4e370ae78f916e22",
           })},
          // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, NO_PREFIX
          // From RFC 9180, Appendix A.3.1 and Tink Java (HpkeTestUtil.java
          // vector 3).
          {{HpkeParameters::KemId::kDhkemX25519HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemX25519HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kX25519PublicKeyHex,
               /*private_key_hex=*/kX25519PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e07aba"
               "42d77a29b62c7af6b2cfda9c1529bb8d23c8",
           })},
          // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, NO_PREFIX
          // From RFC 9180 and Tink Java (HpkeTestUtil.java vector 6).
          {{HpkeParameters::KemId::kDhkemP256HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm256,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemP256HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm256,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kP256PublicKeyHex,
               /*private_key_hex=*/kP256PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "04b2de5915aa2bde7ad85745a632258caba46ed5be81297177dae45cdcbcf4"
               "9c92431ea80763f92f6b22115723a7d092994d40376f7618e9f2ef82d5c440"
               "36e29eca440814ade6c8d5d9246abddaf5740331",
           })},
          // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305,
          // NO_PREFIX
          // From RFC 9180 and Tink Java (HpkeTestUtil.java vector 7).
          {{HpkeParameters::KemId::kDhkemP256HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kChaCha20Poly1305,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemP256HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kChaCha20Poly1305,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kP256PublicKeyHex,
               /*private_key_hex=*/kP256PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "04e0f41a312164058e2c36f1bc977e12a6fec8b13dc5fabc2441ec905bc432"
               "145a0a5e50929815ec6944a3da1a186c0b9b428232086b218af061e9f814d8"
               "bd27808bce0bdb3c656d307f87ffe3bf13b0eb19",
           })},
          // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, TINK
          // From Tink Java (HpkeTestUtil.java vector 8).
          {{HpkeParameters::KemId::kDhkemP256HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128, HpkeParameters::Variant::kTink},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemP256HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kTink,
               /*id_requirement=*/0x886688aa,
               /*public_key_hex=*/kP256PublicKeyHex,
               /*private_key_hex=*/kP256PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "01886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9"
               "ba74234494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"
               "15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22",
           })},
          // DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, CRUNCHY
          // From Tink Java (HpkeTestUtil.java vector 9).
          {{HpkeParameters::KemId::kDhkemP256HkdfSha256,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128,
            HpkeParameters::Variant::kCrunchy},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kDhkemP256HkdfSha256,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kCrunchy,
               /*id_requirement=*/0x886688aa,
               /*public_key_hex=*/kP256PublicKeyHex,
               /*private_key_hex=*/kP256PrivateKeyHex,
               /*plaintext_hex=*/"01",
               /*context_info_hex=*/"02",
               /*ciphertext_hex=*/
               "00886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9"
               "ba74234494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"
               "15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22",
           })},
          // X-Wing, HKDF-SHA256, AES-128-GCM, NO_PREFIX
          // From RFC 9180 / draft-connolly-cfrg-xwing-kem-09 and Tink Java
          // (HpkeTestUtil.java vector 12).
          {{HpkeParameters::KemId::kXWing, HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kXWing,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kXWingPublicKeyHex,
               /*private_key_hex=*/kXWingPrivateKeyHex,
               /*plaintext_hex=*/
               "4265617574792069732074727574682c20747275746820626561757479",
               /*context_info_hex=*/"4f6465206f6e2061204772656369616e2055726e",
               /*ciphertext_hex=*/
               "c326b0c0a30963f331a4212415476bfbd888c8bcaa1b9cb9ed4975d54b0541"
               "a05753f5b7cc62df29cf09152061f1dff1294e50ffa9efdf57ab0fd024a447"
               "150d1c152dda8bfd2cb613f603823c67cfd20282ddecb7c4d8b676f33c8645"
               "40317d5134c76c52959a26c037f09f9c3d74bb58bf969890398bfa71320e0a"
               "96e49c78f11dd5f2dc48bc0b7b5a1bc0f66f9a4e85add8ac3a2f29c85689f8"
               "3035a2a8586240c513354c860700c9811af61c8ec6a384b5b00f385b9983ba"
               "cf8a32c3fbb71ad56112844bdcc83a1b4be754b5b550b4e2d2c712ba85dab3"
               "de4c079547eb68d85b405fffc1bdfa5e163ceb54653c440e5bc6e34b454f71"
               "0853edc704c1232cfa6042a5d7482c880bcc762ab269467e198171280a9d9b"
               "db37d450983a4f3f81b70f6848117a2c9667e8429f1976819e94760f5d8cfe"
               "4ef909c705cec742a6ef06426c9c7f498ce24e52415b3adcd28ef0e3347936"
               "7baa43979c295e88fd532b777ab48e9beb3e4374e8eeadba103edd5e250f92"
               "c96242d6a18f811bbcbb67fc958f18a58d35cc37475bd384574fb69559b057"
               "faa8175b6f436cb1751bfaccd7829db42be19c3e6f89f6db506a1f28a10c80"
               "6b0df33fb1b8e789c6c7537400afafb3a3beccdce24d47bc658e882f97ceb1"
               "a87ce0852a9e6db426b8fce667870412908f05b9768570dca927ddb05fb80f"
               "1242c5208434c83ffd8c20cb661fb5c47b89017ecda1fa54cec5a7204d2092"
               "f57b7176fbbe3b8d0275337135a8cbf7d773042085d93348b6f622d19be146"
               "71fba1953fc6ba3df38a4fe317270efc3b1ed631784bf2aaf777786f44a8b0"
               "677050f130a9b3377c5c269cbe83ded94aab71f6915c76b307c623058020bb"
               "c498bf6f31b923454729a46286cad4eb2a1fbf7efe16c505abd49ad5a055ad"
               "0bd1ca405b1f7145c477f7f4903b90cd474618bb50aead90a3c88fcca75ebd"
               "8f1fa6274c3604c27374e4ea31973394d555442def7c222d2da4678c083771"
               "b08500d460906def458e1121e5d575ae8b21f2b0c6d99439ec39724f65debb"
               "bba504ecfd9f957f8148a5d44db32cadfb6c81e931222080449f100a2f290b"
               "16a56eaa48ce437d6340ec0ba8519869aeff37f3dbefd7d67fb631132029fa"
               "880be3f59560d6d5b6f1c84551d11acc02a0e2706c306936f578ac35f00440"
               "eeb593fc8efb6d387b1452e013488bb6e0966ecd8ee0364bd16ad1df89bc1a"
               "6676b96ead983181d451ea2376a063b685d97e73d4d868552654690482e55f"
               "4547caafb0ea60634bc5b513216cb640b6baebd98d64e786b2f4972d6711b7"
               "e2995908ba43dd855f5fe4d59ee92efb87b59d120dedc8bee364b713c32469"
               "533729ea37492890cab69099586082ce90cddff25aee36467109f41b611ba0"
               "d4a5839e41f3a957a155d0a91eec26a5d51c651b22b259f4b4d23cc8c3d5b8"
               "a4b1c324feb36d93d8a9a97bde22ffd8d3a934dd2154799fd34d0dc17b3e9e"
               "45203e45257376ba800c2abe091ac424c6bebae649533603de6ccb51ed1044"
               "12d7398423a93e0301795d0074249828434d8252d3aa18cd6b428682e02051"
               "e6d2df08463d106aaf2aa3f5528e1392d3b25bb52977b36af81bca74ec1a2a"
               "3b65cd14a8040c43f046d02f877aae69e2a8",
           })},
          // ML-KEM-768, HKDF-SHA256, AES-128-GCM, NO_PREFIX
          // From NIST FIPS 203 and Tink Java (HpkeTestUtil.java vector 13).
          {{HpkeParameters::KemId::kMlKem768,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm128,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kMlKem768,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kMlKem768PublicKeyHex,
               /*private_key_hex=*/kMlKemPrivateKeyHex,
               /*plaintext_hex=*/
               "86526d8f8d975a50785055b1f6120e6e76e1088730919310d486016a1c62b9"
               "a797c5f8842c16260f959c1620d43632975a6c3f309b6891398c8c5a4d3148"
               "1180de",
               /*context_info_hex=*/
               "b254a656608933b934b3f81e8f810214c8135eda92a0614c2b926c4a3075b9"
               "f939e6a3c61309f53e",
               /*ciphertext_hex=*/
               "bd48b97bc2c9ef55bcdf65e5c705aad0c190fb3e4271ca78b567a8d3d7070c"
               "6e73e4637cd3341ece8858335b3fec417a3671720717d15546eafeb2d3b72e"
               "04f87064e2819e90c046085e0704c6589f97d911bf18baf54ca0d07a4ccd95"
               "4ee62226d760750d9a908142d19109e7dca776be514bb851eb33ce34a53324"
               "4a5d12300df204b82484f08696588361a0e93f7295d617e7a8d453d78d940a"
               "251a440d74b4130801765d05edf5aa70dc8e7d5718bc9d9914e241c928cdc7"
               "99d4485572ebfa8c8c25a5d055b2317a9aa53f760a995e370c11f8117b213d"
               "5b129579ea5d959433bf01feb3bf93f42e047daa1e4f108ae82c66887e65fa"
               "8f43995251d55d0ba82df473efaaac43d0a777339f2fa40deb812c7a6ceb1a"
               "15817e9408a0a80164fda5d80194cf6ffbbc9fcd21cceac5c091c718486afd"
               "22f046c4d62d9e93c3bccee6f3c7629d5f30e4c7509cc1ba70dcc1d12d4609"
               "aa1525c5a2ad75135a4fdc044ba72e77282a7ff89e976a0d7ee81def2df82e"
               "b96e7057ff9ee94a598376d16b65b918e845be331fea83f391b7eb504e6f1c"
               "98a17867dec5829eac0e63672f09b9ccf3b9b489e191bd5cfceb1da0bb4d18"
               "ae6e9a15d794f81f36c3148dd288c6a3ebd705a2f601acce37551dda6cc1f8"
               "a4a7ea11a2c86254ceca99486d6634251cbda030b9642f68a6f46dcbef3c94"
               "c65f772ecb8341703c30068a3c9fcd263a6149d5a6dbeff9b569f7f68d2373"
               "3f498fbee12d402f980532f3d1ec83b9828ceafb54518447bc2393c973fff6"
               "68ff54fa7958205e3be4eca40fd2523327568b5245355c828a9f6294ed3ef1"
               "79b5eb16bc1e43f61ab069d10c89f59cf447d5a61c8498ff84f48a7cd76832"
               "c8d694e5b090c176caf81be027215cdfaadf5e05e2c80155ffc6eebb1589f3"
               "3abaee00ba8bc7f4794561e9a54616bd505896517940ce8adb2d9e2d0d7781"
               "75a19c987f5791b41af272e89e43c73436fbfb2ead8e8624acf81d81694f21"
               "a13cd1e13ea818f46f66ddce1e93e20f4c3b2fa820ebd224937053c4ed1404"
               "802634a0b1cd3763970ba6f66e13c6e1d833c9e80e4c041cd1c4947cc9cf0b"
               "70fc78b55b2244527bbedc6e618bf96261bec109320ee1a94e84dedd003d37"
               "deca5bc6ac6cd3bb8fa6a92fd62b331179f1557632f91cfb5cd327e643aa86"
               "7dab7801e5e91317191b3ddcec231aa6c1c07c371b5b5a02340cba092605e3"
               "8642aa190275d8324757d1330a0bfef15841e39c9430cb89ce596e0b715b26"
               "aa7c6c4b642f914a9da8ae77f045a112dfd3a0aa9616a817a09c5449b8831a"
               "d12bd17af81af7a5808e572b28c75591bcf69ab8077f8e067df75f4365fa9b"
               "70de24ed1422ea3229d85d0bfb503bc2bffd89c74055b76758cea078a05bd1"
               "2c793a1f9c78f5e90f44d89d5bd14a211ae149c91da17b6ac46774cc3c73a8"
               "07edbfdb3e33002daa2dc2758824435dfc6a0ddfe0bd1db083bf5f5d8e7b18"
               "abd1de1a8706f5c0c8a762d0a3d3f1ce02813345937034b973f94b6114651a"
               "58aacfbe50e7d9e0aac571eac64b27b296bae1254505ec797a79b772fa60bc"
               "8f81bfe367af4ee02107c090f6a60bf8e9f547fd7937ad607ece7d7791817f"
               "55411c551f2de6f1a5b6662868d290dc884377a8a225",
           })},
          // ML-KEM-1024, HKDF-SHA256, AES-256-GCM, NO_PREFIX
          // From NIST FIPS 203 and Tink Java (HpkeTestUtil.java vector 14).
          {{HpkeParameters::KemId::kMlKem1024,
            HpkeParameters::KdfId::kHkdfSha256,
            HpkeParameters::AeadId::kAesGcm256,
            HpkeParameters::Variant::kNoPrefix},
           MakeHpkeTestVector(HpkeTestVectorParams{
               /*kem_id=*/HpkeParameters::KemId::kMlKem1024,
               /*kdf_id=*/HpkeParameters::KdfId::kHkdfSha256,
               /*aead_id=*/HpkeParameters::AeadId::kAesGcm256,
               /*variant=*/HpkeParameters::Variant::kNoPrefix,
               /*id_requirement=*/std::nullopt,
               /*public_key_hex=*/kMlKem1024PublicKeyHex,
               /*private_key_hex=*/kMlKemPrivateKeyHex,
               /*plaintext_hex=*/
               "c8a4153f9b7e2d06c5478f1a3e6d9c0b25748f3e9a6c1b4d8e7f5a2b0d9e8c"
               "1f7a4b6d3e9f2a7c5b8e1d4f0a3c7b8e2d5f1a4c9b8d2e6f3a7c1b5d9e",
               /*context_info_hex=*/
               "b9e8c67f3a2d1e0c4b59f7d6a5c3b2e18d9f0a786e5c4d3b2a1f0987e6d5c4"
               "b3",
               /*ciphertext_hex=*/
               "35ab4e29f97d2828aeb7f746f1eaf17fd41a20542cfc6df50009f6558dfb5c"
               "a5325e1aeed36a8d51bf4eed0244b655b8a5b1434325424669d01f6133b4ac"
               "96b1e9e46dd34fede463f92255bd55c76269858fbbebfc05d69b2873a16f53"
               "da8f16d82070ff41a8094b457e0d6695f3b01aa10764fe164a5b88ab822b7d"
               "996056ebb29a979cecb9a06965181337f60d7690fefb6fc5e37617c6beee69"
               "2ac9777bfa0cb792c6ccc2fff66dc986e2df0e94ec88ec3d06a4fdbee5d56a"
               "53800b6c286e683b1cb603184754414ee5e459a86d3800b435c6d593c04548"
               "7cd18c33b1131011d4e390c8417a6b2480a077ddff5b25c48efe4b79d0b0c9"
               "7ee8546946b52e59a95ea55058a6f265b39c62402831bd9cff4736b7602e79"
               "9d9501e1e134ae33f63d820a144dad11ed2ef598ae648b425fb95600a7a4a7"
               "007bd639a110b3583d65c5e224f699681971eeeccdbf49f2ef22e72c4b14a2"
               "3034ea16c4e0ca61fc1a0a1d25081110a5dcebd5d421d90b64ba00ac0015bc"
               "1b3ec8d59402b351a7099fc6e6f1f1484bb614d3ad7c02af2dbac41615d0c1"
               "4de681f65a229228782f9f692a2d9fd4ed04bceaa429dcc0bc4610c275487d"
               "74fa8dd08d1ac0f2242bb0387ac980088f6187834717cfc856d32a99d7e68f"
               "f318d5c562202ef766274a76c1e6ed5c42ae7fa9140907102a11ca4a1ecf35"
               "e133b41788e7362a8a3eb6bff94523ff1315b076d5e1a81a593cac13235ebd"
               "8d95942026bdda9e0d7cd8ba186344a7d8c407fe05522ff0026d47fd759dc0"
               "9f843cf424ffcce3a18423f0c0b17a816dbaeb950cfcfdc9bc150b51bdf019"
               "022c95cd03940f3b6611e76487962f64e18c1026cdaa74d24f390942ec77fc"
               "9cfb45260153a68fa22ed7d283306539b66aa0dc03abeeb79ac99d9bc84a7c"
               "822b57c41b7eeadd0037380724b1780f24b265e09988fa40e6f59d6dfb3903"
               "e4c55b6f0e0c204fe6b7cfc0d172f58614cf1f76ada5b4e1fa27606c182970"
               "fd032a8d81917fe5a11efad9dd41cfc805b3211c2c2eb59f65fe0c7af68a39"
               "3a12c78de044a9c2678afff346f7fc6c69427bbe1f9068fef9478c788912ac"
               "87340297aa1d685e06a7c86ac141127cc1f6dc7c20da5b7f61289b4e881390"
               "e4ec28d5ef64da41c2701cc74a24e9212f17388102224cefe260ece85faceb"
               "3d1f5e67a2af99fbd10eb951d038cf455901f8996dc1bc091f41d8543d4440"
               "684872742ea50ebb21cf4ac21d5148e1588f9173943010ab0d00cd2a04c72c"
               "68a897768cf6ef195c3f7650462a7b3bc5b9edeba690dcc3ba8e818cb5e5c2"
               "b8a7c57905f07c711e587e33bedba755cff2f2c41177a0ea984d377aea7b01"
               "48c8def3c515924351b30eadf795610d386e10e37001594fa66be43a1d39a8"
               "3a4737b31d04fb4310fd62fa56fbaa4a2c6dbb7029be979887bb2635f2863b"
               "b92aa6f145b44170fe476c8969c7de535deaf7f302673144c90c24dbc6df6b"
               "b81b72e24a091aa120f75cbb659caaae465b66ea64db727cead53d65f167a3"
               "cab1e97e4c7f3e9332500ae9d1745a725289f1327c8cfd6d9380d45eb7bf03"
               "e37825fa8e438b462e8db54351528f9550b763a003a46335f79f3ada75f916"
               "b028a364a16c527d2ea9a21fd587e8a34339d66156d6a0055a15a51d1206a8"
               "24d2ae94e95382e888150ada59d606ac4b17f855563c737f50ec449a7d7c1a"
               "7cf2801a81578a5d0c6afbecf25cde3b333bc1d25af54c67a5b21293338814"
               "0810a1dad0895add3452c0ad0e4cd83b055c5ded7c8f463a28154948acc99e"
               "6695dc523a8255c1ffb29b86d3330ad153776bb340dad43c5ea59a69009d3d"
               "ff057e019cddcd0ac055ba22ba04cb241f3b082c05695a5b07602194d714e8"
               "4bad39e37017eacd7ca7026c307c67a4f63d08a0b0f5155a6b9a79564a10cd"
               "23cecf28659a04a7732aebfb9edaa486bcdf6fbd1a115477f221027a21f9e3"
               "a1db0ce995fd1b92759cfa3778d202a43cbc767a2cd4bf7cf7461e74de3e2a"
               "eaeb1a30884563c3f44928085427f6205b43d2a93cb7927bd0eca44783d1c6"
               "5cad1d968e434daf6b851ab2b8d9f1516afb9ea65dac8715a1e83eee0be7c3"
               "1a82d33d581a910baae404c06e954cf3281d19c3665756cf262f6d028832a6"
               "bf16cfc860f7a7538a19e1558e2fdaa56bd26ecba4c7342f28250f498cbc10"
               "75b181c762dd3afbdaa42f3267f736faecdc81f49b1a4d2eaff96b635a505f"
               "1ae8b5210ca44fba8f1c0f2de96a38b35e64305d58c0be8f3cff0aa51f7691"
               "39b6308b9ec4da6844709cda17d47cfa7deef634b8fa3215f2c38b1d3057cd"
               "3c",
           })},
      });
  return *test_vectors;
}

}  // namespace

std::string P256PointAsString() { return HexDecodeOrDie(kP256PublicKeyHex); }

RestrictedData P256SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kP256PrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string P384PointAsString() { return HexDecodeOrDie(kP384PublicKeyHex); }

RestrictedData P384SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kP384PrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string P521PointAsString() { return HexDecodeOrDie(kP521PublicKeyHex); }

RestrictedData P521SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kP521PrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string X25519PublicValue() { return HexDecodeOrDie(kX25519PublicKeyHex); }

RestrictedData X25519SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kX25519PrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string XWingPublicValue() { return HexDecodeOrDie(kXWingPublicKeyHex); }

RestrictedData XWingSecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kXWingPrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string MlKem768PublicValue() {
  return HexDecodeOrDie(kMlKem768PublicKeyHex);
}

RestrictedData MlKem768SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kMlKemPrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

std::string MlKem1024PublicValue() {
  return HexDecodeOrDie(kMlKem1024PublicKeyHex);
}

RestrictedData MlKem1024SecretValue() {
  return RestrictedData(
      SecretDataFromStringView(HexDecodeOrDie(kMlKemPrivateKeyHex)),
      InsecureSecretKeyAccess::Get());
}

const std::vector<HybridTestVector>& CreateHpkeTestVectors() {
  static const absl::NoDestructor<std::vector<HybridTestVector>> test_vectors(
      [] {
        const HpkeTestVectorMap& test_vectors_map = CreateHpkeTestVectorsMap();
        std::vector<HybridTestVector> result;
        result.reserve(test_vectors_map.size());
        for (const auto& [unused_params, test_vector] : test_vectors_map) {
          result.push_back(test_vector);
        }
        return result;
      }());
  return *test_vectors;
}

const HybridTestVector& GetHpkeTestVector(HpkeParameters::KemId kem_id,
                                          HpkeParameters::KdfId kdf_id,
                                          HpkeParameters::AeadId aead_id,
                                          HpkeParameters::Variant variant) {
  const HpkeTestVectorMap& test_vectors_map = CreateHpkeTestVectorsMap();
  auto it =
      test_vectors_map.find(std::make_tuple(kem_id, kdf_id, aead_id, variant));
  ABSL_CHECK(it != test_vectors_map.end())
      << "No HPKE test vector found for kem_id: " << static_cast<int>(kem_id)
      << ", kdf_id: " << static_cast<int>(kdf_id)
      << ", aead_id: " << static_cast<int>(aead_id)
      << ", variant: " << static_cast<int>(variant);
  return it->second;
}

const std::vector<HpkeNistCurveTestCase>& CreateHpkeNistCurveTestCases() {
  static const absl::NoDestructor<std::vector<HpkeNistCurveTestCase>>
      test_cases([]() {
        absl::StatusOr<HpkeParameters> p256_params =
            HpkeParameters::Builder()
                .SetVariant(HpkeParameters::Variant::kTink)
                .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
                .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
                .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
                .Build();
        ABSL_CHECK_OK(p256_params.status());
        absl::StatusOr<HpkePublicKey> p256_public_key = HpkePublicKey::Create(
            *p256_params, P256PointAsString(),
            /*id_requirement=*/0x02030400, GetPartialKeyAccess());
        ABSL_CHECK_OK(p256_public_key.status());
        absl::StatusOr<HpkePrivateKey> p256_private_key =
            HpkePrivateKey::Create(*p256_public_key, P256SecretValue(),
                                   GetPartialKeyAccess());
        ABSL_CHECK_OK(p256_private_key.status());

        absl::StatusOr<HpkeParameters> p384_params =
            HpkeParameters::Builder()
                .SetVariant(HpkeParameters::Variant::kCrunchy)
                .SetKemId(HpkeParameters::KemId::kDhkemP384HkdfSha384)
                .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
                .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
                .Build();
        ABSL_CHECK_OK(p384_params.status());
        absl::StatusOr<HpkePublicKey> p384_public_key = HpkePublicKey::Create(
            *p384_params, P384PointAsString(),
            /*id_requirement=*/0x01030005, GetPartialKeyAccess());
        ABSL_CHECK_OK(p384_public_key.status());
        absl::StatusOr<HpkePrivateKey> p384_private_key =
            HpkePrivateKey::Create(*p384_public_key, P384SecretValue(),
                                   GetPartialKeyAccess());
        ABSL_CHECK_OK(p384_private_key.status());

        absl::StatusOr<HpkeParameters> p521_params =
            HpkeParameters::Builder()
                .SetVariant(HpkeParameters::Variant::kNoPrefix)
                .SetKemId(HpkeParameters::KemId::kDhkemP521HkdfSha512)
                .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
                .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
                .Build();
        ABSL_CHECK_OK(p521_params.status());
        absl::StatusOr<HpkePublicKey> p521_public_key = HpkePublicKey::Create(
            *p521_params, P521PointAsString(),
            /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
        ABSL_CHECK_OK(p521_public_key.status());
        absl::StatusOr<HpkePrivateKey> p521_private_key =
            HpkePrivateKey::Create(*p521_public_key, P521SecretValue(),
                                   GetPartialKeyAccess());
        ABSL_CHECK_OK(p521_private_key.status());

        return std::vector<HpkeNistCurveTestCase>{
            HpkeNistCurveTestCase{
                subtle::EllipticCurveType::NIST_P256,
                HpkeParameters::KemId::kDhkemP256HkdfSha256,
                HpkeParameters::KdfId::kHkdfSha256,
                HpkeParameters::AeadId::kAesGcm128,
                HpkeParameters::Variant::kTink,
                /*id_requirement=*/0x02030400,
                /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5),
                std::make_shared<const HpkePrivateKey>(
                    *std::move(p256_private_key))},
            HpkeNistCurveTestCase{
                subtle::EllipticCurveType::NIST_P384,
                HpkeParameters::KemId::kDhkemP384HkdfSha384,
                HpkeParameters::KdfId::kHkdfSha384,
                HpkeParameters::AeadId::kAesGcm256,
                HpkeParameters::Variant::kCrunchy,
                /*id_requirement=*/0x01030005,
                /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5),
                std::make_shared<const HpkePrivateKey>(
                    *std::move(p384_private_key))},
            HpkeNistCurveTestCase{subtle::EllipticCurveType::NIST_P521,
                                  HpkeParameters::KemId::kDhkemP521HkdfSha512,
                                  HpkeParameters::KdfId::kHkdfSha512,
                                  HpkeParameters::AeadId::kChaCha20Poly1305,
                                  HpkeParameters::Variant::kNoPrefix,
                                  /*id_requirement=*/std::nullopt,
                                  /*output_prefix=*/"",
                                  std::make_shared<const HpkePrivateKey>(
                                      *std::move(p521_private_key))},
        };
      }());
  return *test_cases;
}

const std::vector<HpkeMlKemTestCase>& CreateHpkeMlKemTestCases() {
  static const absl::NoDestructor<std::vector<HpkeMlKemTestCase>> test_cases(
      []() {
        const auto& mlkem768_key = dynamic_cast<const HpkePrivateKey&>(
            *GetHpkeTestVector(HpkeParameters::KemId::kMlKem768,
                               HpkeParameters::KdfId::kHkdfSha256,
                               HpkeParameters::AeadId::kAesGcm128,
                               HpkeParameters::Variant::kNoPrefix)
                 .hybrid_private_key);
        const auto& mlkem1024_key = dynamic_cast<const HpkePrivateKey&>(
            *GetHpkeTestVector(HpkeParameters::KemId::kMlKem1024,
                               HpkeParameters::KdfId::kHkdfSha256,
                               HpkeParameters::AeadId::kAesGcm256,
                               HpkeParameters::Variant::kNoPrefix)
                 .hybrid_private_key);
        return std::vector<HpkeMlKemTestCase>{
            HpkeMlKemTestCase{
                HpkeParameters::KemId::kMlKem768, MlKemKeySize::ML_KEM768, 1184,
                std::make_shared<const HpkePrivateKey>(mlkem768_key)},
            HpkeMlKemTestCase{
                HpkeParameters::KemId::kMlKem1024, MlKemKeySize::ML_KEM1024,
                1568, std::make_shared<const HpkePrivateKey>(mlkem1024_key)},
        };
      }());
  return *test_cases;
}

absl::StatusOr<HpkeKeyPairBytes> GetHpkeNistCurveKeyPairBytes(
    subtle::EllipticCurveType curve) {
  switch (curve) {
    case subtle::EllipticCurveType::NIST_P256:
      return HpkeKeyPairBytes{P256PointAsString(), P256SecretValue()};
    case subtle::EllipticCurveType::NIST_P384:
      return HpkeKeyPairBytes{P384PointAsString(), P384SecretValue()};
    case subtle::EllipticCurveType::NIST_P521:
      return HpkeKeyPairBytes{P521PointAsString(), P521SecretValue()};
    default:
      return absl::InvalidArgumentError("Unsupported curve");
  }
}

HpkeKeyPairBytes GetHpkeMlKemKeyPairBytes(MlKemKeySize key_size) {
  if (key_size == MlKemKeySize::ML_KEM768) {
    return HpkeKeyPairBytes{MlKem768PublicValue(), MlKem768SecretValue()};
  }
  return HpkeKeyPairBytes{MlKem1024PublicValue(), MlKem1024SecretValue()};
}

HpkeKeyPairBytes GetHpkeX25519KeyPairBytes() {
  return HpkeKeyPairBytes{X25519PublicValue(), X25519SecretValue()};
}

HpkeKeyPairBytes GetHpkeXWingKeyPairBytes() {
  return HpkeKeyPairBytes{XWingPublicValue(), XWingSecretValue()};
}

}  // namespace crypto::tink::internal
