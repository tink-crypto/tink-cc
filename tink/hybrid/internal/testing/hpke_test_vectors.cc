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
#include <string>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hybrid_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::util::SecretDataFromStringView;

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
std::string P256PointAsString() {
  std::string pub_key_x_p256_hex =
      "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
  std::string pub_key_y_p256_hex =
      "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p256_hex, pub_key_y_p256_hex));
}

RestrictedData P256SecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

HybridTestVector CreateTestVector0() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba742"
                     "34494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c1"
                     "15cf17875f59b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

HybridTestVector CreateTestVector1() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters,
      HexDecodeOrDie(
          "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(HexDecodeOrDie("52c4a758a802cd8b936eceea314432798d5baf2d7e"
                                    "9235dc084ab1b9cfa2f736"),
                     InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("c202f5f26a59c446531b9e4e880f8730ff0aed444699cb1cd69a2c60e"
                     "07aba42d77a29b62c7af6b2cfda9c1529bb8d23c8"));
}

// AES_256_GCM
HybridTestVector CreateTestVector2() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04b2de5915aa2bde7ad85745a632258caba46ed5be81297177dae45cd"
                     "cbcf49c92431ea80763f92f6b22115723a7d092994d40376f7618e9f2"
                     "ef82d5c44036e29eca440814ade6c8d5d9246abddaf5740331"));
}

// CHACHA20_POLY1305
HybridTestVector CreateTestVector3() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie("04e0f41a312164058e2c36f1bc977e12a6fec8b13dc5fabc2441ec905"
                     "bc432145a0a5e50929815ec6944a3da1a186c0b9b428232086b218af0"
                     "61e9f814d8bd27808bce0bdb3c656d307f87ffe3bf13b0eb19"));
}

// TINK
HybridTestVector CreateTestVector4() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x886688aa,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "01886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"
          "4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"
          "b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

// CRUNCHY
HybridTestVector CreateTestVector5() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x886688aa,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key), HexDecodeOrDie("01"),
      HexDecodeOrDie("02"),
      HexDecodeOrDie(
          "00886688aa04d7d800cab3d3c0104899e137656a3a23a58e1efe41310ea5e9ba7423"
          "4494b10da4286d4baf4641c38d509d28cb21c4694461ccd6258864c115cf17875f59"
          "b069dffc8427cfb7f277ed4e370ae78f916e22"));
}

HybridTestVector CreateTestVectorXWing() {
  std::string private_key_bytes = HexDecodeOrDie(
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
  RestrictedData raw_private_key =
      RestrictedData(SecretDataFromStringView(private_key_bytes),
                     InsecureSecretKeyAccess::Get());
  std::string raw_public_key = HexDecodeOrDie(
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
      "eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534");

  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, raw_public_key, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, raw_private_key, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key),
      HexDecodeOrDie(
          "4265617574792069732074727574682c20747275746820626561757479"),
      HexDecodeOrDie("4f6465206f6e2061204772656369616e2055726e"),
      HexDecodeOrDie(
          "c326b0c0a30963f331a4212415476bfbd888c8bcaa1b9cb9ed4975d54b0541a05753"
          "f5b7cc62df29cf09152061f1dff1294e50ffa9efdf57ab0fd024a447150d1c152dda"
          "8bfd2cb613f603823c67cfd20282ddecb7c4d8b676f33c864540317d5134c76c5295"
          "9a26c037f09f9c3d74bb58bf969890398bfa71320e0a96e49c78f11dd5f2dc48bc0b"
          "7b5a1bc0f66f9a4e85add8ac3a2f29c85689f83035a2a8586240c513354c860700c9"
          "811af61c8ec6a384b5b00f385b9983bacf8a32c3fbb71ad56112844bdcc83a1b4be7"
          "54b5b550b4e2d2c712ba85dab3de4c079547eb68d85b405fffc1bdfa5e163ceb5465"
          "3c440e5bc6e34b454f710853edc704c1232cfa6042a5d7482c880bcc762ab269467e"
          "198171280a9d9bdb37d450983a4f3f81b70f6848117a2c9667e8429f1976819e9476"
          "0f5d8cfe4ef909c705cec742a6ef06426c9c7f498ce24e52415b3adcd28ef0e33479"
          "367baa43979c295e88fd532b777ab48e9beb3e4374e8eeadba103edd5e250f92c962"
          "42d6a18f811bbcbb67fc958f18a58d35cc37475bd384574fb69559b057faa8175b6f"
          "436cb1751bfaccd7829db42be19c3e6f89f6db506a1f28a10c806b0df33fb1b8e789"
          "c6c7537400afafb3a3beccdce24d47bc658e882f97ceb1a87ce0852a9e6db426b8fc"
          "e667870412908f05b9768570dca927ddb05fb80f1242c5208434c83ffd8c20cb661f"
          "b5c47b89017ecda1fa54cec5a7204d2092f57b7176fbbe3b8d0275337135a8cbf7d7"
          "73042085d93348b6f622d19be14671fba1953fc6ba3df38a4fe317270efc3b1ed631"
          "784bf2aaf777786f44a8b0677050f130a9b3377c5c269cbe83ded94aab71f6915c76"
          "b307c623058020bbc498bf6f31b923454729a46286cad4eb2a1fbf7efe16c505abd4"
          "9ad5a055ad0bd1ca405b1f7145c477f7f4903b90cd474618bb50aead90a3c88fcca7"
          "5ebd8f1fa6274c3604c27374e4ea31973394d555442def7c222d2da4678c083771b0"
          "8500d460906def458e1121e5d575ae8b21f2b0c6d99439ec39724f65debbbba504ec"
          "fd9f957f8148a5d44db32cadfb6c81e931222080449f100a2f290b16a56eaa48ce43"
          "7d6340ec0ba8519869aeff37f3dbefd7d67fb631132029fa880be3f59560d6d5b6f1"
          "c84551d11acc02a0e2706c306936f578ac35f00440eeb593fc8efb6d387b1452e013"
          "488bb6e0966ecd8ee0364bd16ad1df89bc1a6676b96ead983181d451ea2376a063b6"
          "85d97e73d4d868552654690482e55f4547caafb0ea60634bc5b513216cb640b6baeb"
          "d98d64e786b2f4972d6711b7e2995908ba43dd855f5fe4d59ee92efb87b59d120ded"
          "c8bee364b713c32469533729ea37492890cab69099586082ce90cddff25aee364671"
          "09f41b611ba0d4a5839e41f3a957a155d0a91eec26a5d51c651b22b259f4b4d23cc8"
          "c3d5b8a4b1c324feb36d93d8a9a97bde22ffd8d3a934dd2154799fd34d0dc17b3e9e"
          "45203e45257376ba800c2abe091ac424c6bebae649533603de6ccb51ed104412d739"
          "8423a93e0301795d0074249828434d8252d3aa18cd6b428682e02051e6d2df08463d"
          "106aaf2aa3f5528e1392d3b25bb52977b36af81bca74ec1a2a3b65cd14a8040c43f0"
          "46d02f877aae69e2a8"));
}

HybridTestVector CreateTestVectorMlKem768() {
  std::string private_key_bytes = HexDecodeOrDie(
      "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79"
      "d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f");
  RestrictedData raw_private_key =
      RestrictedData(SecretDataFromStringView(private_key_bytes),
                     InsecureSecretKeyAccess::Get());
  std::string raw_public_key = HexDecodeOrDie(
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
      "162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f028");

  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem768)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, raw_public_key, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, raw_private_key, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key),
      HexDecodeOrDie(
          "86526d8f8d975a50785055b1f6120e6e76e1088730919310d486016a1c62b9a797c5"
          "f8842c16260f959c1620d43632975a6c3f309b6891398c8c5a4d31481180de"),
      HexDecodeOrDie("b254a656608933b934b3f81e8f810214c8135eda92a0614c2b926c4a3"
                     "075b9f939e6a3c61309f53e"),
      HexDecodeOrDie(
          "bd48b97bc2c9ef55bcdf65e5c705aad0c190fb3e4271ca78b567a8d3d7070c6e73e4"
          "637cd3341ece8858335b3fec417a3671720717d15546eafeb2d3b72e04f87064e281"
          "9e90c046085e0704c6589f97d911bf18baf54ca0d07a4ccd954ee62226d760750d9a"
          "908142d19109e7dca776be514bb851eb33ce34a533244a5d12300df204b82484f086"
          "96588361a0e93f7295d617e7a8d453d78d940a251a440d74b4130801765d05edf5aa"
          "70dc8e7d5718bc9d9914e241c928cdc799d4485572ebfa8c8c25a5d055b2317a9aa5"
          "3f760a995e370c11f8117b213d5b129579ea5d959433bf01feb3bf93f42e047daa1e"
          "4f108ae82c66887e65fa8f43995251d55d0ba82df473efaaac43d0a777339f2fa40d"
          "eb812c7a6ceb1a15817e9408a0a80164fda5d80194cf6ffbbc9fcd21cceac5c091c7"
          "18486afd22f046c4d62d9e93c3bccee6f3c7629d5f30e4c7509cc1ba70dcc1d12d46"
          "09aa1525c5a2ad75135a4fdc044ba72e77282a7ff89e976a0d7ee81def2df82eb96e"
          "7057ff9ee94a598376d16b65b918e845be331fea83f391b7eb504e6f1c98a17867de"
          "c5829eac0e63672f09b9ccf3b9b489e191bd5cfceb1da0bb4d18ae6e9a15d794f81f"
          "36c3148dd288c6a3ebd705a2f601acce37551dda6cc1f8a4a7ea11a2c86254ceca99"
          "486d6634251cbda030b9642f68a6f46dcbef3c94c65f772ecb8341703c30068a3c9f"
          "cd263a6149d5a6dbeff9b569f7f68d23733f498fbee12d402f980532f3d1ec83b982"
          "8ceafb54518447bc2393c973fff668ff54fa7958205e3be4eca40fd2523327568b52"
          "45355c828a9f6294ed3ef179b5eb16bc1e43f61ab069d10c89f59cf447d5a61c8498"
          "ff84f48a7cd76832c8d694e5b090c176caf81be027215cdfaadf5e05e2c80155ffc6"
          "eebb1589f33abaee00ba8bc7f4794561e9a54616bd505896517940ce8adb2d9e2d0d"
          "778175a19c987f5791b41af272e89e43c73436fbfb2ead8e8624acf81d81694f21a1"
          "3cd1e13ea818f46f66ddce1e93e20f4c3b2fa820ebd224937053c4ed1404802634a0"
          "b1cd3763970ba6f66e13c6e1d833c9e80e4c041cd1c4947cc9cf0b70fc78b55b2244"
          "527bbedc6e618bf96261bec109320ee1a94e84dedd003d37deca5bc6ac6cd3bb8fa6"
          "a92fd62b331179f1557632f91cfb5cd327e643aa867dab7801e5e91317191b3ddcec"
          "231aa6c1c07c371b5b5a02340cba092605e38642aa190275d8324757d1330a0bfef1"
          "5841e39c9430cb89ce596e0b715b26aa7c6c4b642f914a9da8ae77f045a112dfd3a0"
          "aa9616a817a09c5449b8831ad12bd17af81af7a5808e572b28c75591bcf69ab8077f"
          "8e067df75f4365fa9b70de24ed1422ea3229d85d0bfb503bc2bffd89c74055b76758"
          "cea078a05bd12c793a1f9c78f5e90f44d89d5bd14a211ae149c91da17b6ac46774cc"
          "3c73a807edbfdb3e33002daa2dc2758824435dfc6a0ddfe0bd1db083bf5f5d8e7b18"
          "abd1de1a8706f5c0c8a762d0a3d3f1ce02813345937034b973f94b6114651a58aacf"
          "be50e7d9e0aac571eac64b27b296bae1254505ec797a79b772fa60bc8f81bfe367af"
          "4ee02107c090f6a60bf8e9f547fd7937ad607ece7d7791817f55411c551f2de6f1a5"
          "b6662868d290dc884377a8a225"));
}

HybridTestVector CreateTestVectorMlKem1024() {
  std::string private_key_bytes = HexDecodeOrDie(
      "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79"
      "d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f");
  RestrictedData raw_private_key =
      RestrictedData(SecretDataFromStringView(private_key_bytes),
                     InsecureSecretKeyAccess::Get());
  std::string raw_public_key = HexDecodeOrDie(
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
      "bad10738ad04cc752bc20c394746850e0c4847db");

  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem1024)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, raw_public_key, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, raw_private_key, GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  return HybridTestVector(
      std::make_shared<HpkePrivateKey>(*private_key),
      HexDecodeOrDie(
          "c8a4153f9b7e2d06c5478f1a3e6d9c0b25748f3e9a6c1b4d8e7f5a2b0d9e8c1f7a4b"
          "6d3e9f2a7c5b8e1d4f0a3c7b8e2d5f1a4c9b8d2e6f3a7c1b5d9e"),
      HexDecodeOrDie(
          "b9e8c67f3a2d1e0c4b59f7d6a5c3b2e18d9f0a786e5c4d3b2a1f0987e6d5c4b3"),
      HexDecodeOrDie(
          "35ab4e29f97d2828aeb7f746f1eaf17fd41a20542cfc6df50009f6558dfb5ca5325e"
          "1aeed36a8d51bf4eed0244b655b8a5b1434325424669d01f6133b4ac96b1e9e46dd3"
          "4fede463f92255bd55c76269858fbbebfc05d69b2873a16f53da8f16d82070ff41a8"
          "094b457e0d6695f3b01aa10764fe164a5b88ab822b7d996056ebb29a979cecb9a069"
          "65181337f60d7690fefb6fc5e37617c6beee692ac9777bfa0cb792c6ccc2fff66dc9"
          "86e2df0e94ec88ec3d06a4fdbee5d56a53800b6c286e683b1cb603184754414ee5e4"
          "59a86d3800b435c6d593c045487cd18c33b1131011d4e390c8417a6b2480a077ddff"
          "5b25c48efe4b79d0b0c97ee8546946b52e59a95ea55058a6f265b39c62402831bd9c"
          "ff4736b7602e799d9501e1e134ae33f63d820a144dad11ed2ef598ae648b425fb956"
          "00a7a4a7007bd639a110b3583d65c5e224f699681971eeeccdbf49f2ef22e72c4b14"
          "a23034ea16c4e0ca61fc1a0a1d25081110a5dcebd5d421d90b64ba00ac0015bc1b3e"
          "c8d59402b351a7099fc6e6f1f1484bb614d3ad7c02af2dbac41615d0c14de681f65a"
          "229228782f9f692a2d9fd4ed04bceaa429dcc0bc4610c275487d74fa8dd08d1ac0f2"
          "242bb0387ac980088f6187834717cfc856d32a99d7e68ff318d5c562202ef766274a"
          "76c1e6ed5c42ae7fa9140907102a11ca4a1ecf35e133b41788e7362a8a3eb6bff945"
          "23ff1315b076d5e1a81a593cac13235ebd8d95942026bdda9e0d7cd8ba186344a7d8"
          "c407fe05522ff0026d47fd759dc09f843cf424ffcce3a18423f0c0b17a816dbaeb95"
          "0cfcfdc9bc150b51bdf019022c95cd03940f3b6611e76487962f64e18c1026cdaa74"
          "d24f390942ec77fc9cfb45260153a68fa22ed7d283306539b66aa0dc03abeeb79ac9"
          "9d9bc84a7c822b57c41b7eeadd0037380724b1780f24b265e09988fa40e6f59d6dfb"
          "3903e4c55b6f0e0c204fe6b7cfc0d172f58614cf1f76ada5b4e1fa27606c182970fd"
          "032a8d81917fe5a11efad9dd41cfc805b3211c2c2eb59f65fe0c7af68a393a12c78d"
          "e044a9c2678afff346f7fc6c69427bbe1f9068fef9478c788912ac87340297aa1d68"
          "5e06a7c86ac141127cc1f6dc7c20da5b7f61289b4e881390e4ec28d5ef64da41c270"
          "1cc74a24e9212f17388102224cefe260ece85faceb3d1f5e67a2af99fbd10eb951d0"
          "38cf455901f8996dc1bc091f41d8543d4440684872742ea50ebb21cf4ac21d5148e1"
          "588f9173943010ab0d00cd2a04c72c68a897768cf6ef195c3f7650462a7b3bc5b9ed"
          "eba690dcc3ba8e818cb5e5c2b8a7c57905f07c711e587e33bedba755cff2f2c41177"
          "a0ea984d377aea7b0148c8def3c515924351b30eadf795610d386e10e37001594fa6"
          "6be43a1d39a83a4737b31d04fb4310fd62fa56fbaa4a2c6dbb7029be979887bb2635"
          "f2863bb92aa6f145b44170fe476c8969c7de535deaf7f302673144c90c24dbc6df6b"
          "b81b72e24a091aa120f75cbb659caaae465b66ea64db727cead53d65f167a3cab1e9"
          "7e4c7f3e9332500ae9d1745a725289f1327c8cfd6d9380d45eb7bf03e37825fa8e43"
          "8b462e8db54351528f9550b763a003a46335f79f3ada75f916b028a364a16c527d2e"
          "a9a21fd587e8a34339d66156d6a0055a15a51d1206a824d2ae94e95382e888150ada"
          "59d606ac4b17f855563c737f50ec449a7d7c1a7cf2801a81578a5d0c6afbecf25cde"
          "3b333bc1d25af54c67a5b212933388140810a1dad0895add3452c0ad0e4cd83b055c"
          "5ded7c8f463a28154948acc99e6695dc523a8255c1ffb29b86d3330ad153776bb340"
          "dad43c5ea59a69009d3dff057e019cddcd0ac055ba22ba04cb241f3b082c05695a5b"
          "07602194d714e84bad39e37017eacd7ca7026c307c67a4f63d08a0b0f5155a6b9a79"
          "564a10cd23cecf28659a04a7732aebfb9edaa486bcdf6fbd1a115477f221027a21f9"
          "e3a1db0ce995fd1b92759cfa3778d202a43cbc767a2cd4bf7cf7461e74de3e2aeaeb"
          "1a30884563c3f44928085427f6205b43d2a93cb7927bd0eca44783d1c65cad1d968e"
          "434daf6b851ab2b8d9f1516afb9ea65dac8715a1e83eee0be7c31a82d33d581a910b"
          "aae404c06e954cf3281d19c3665756cf262f6d028832a6bf16cfc860f7a7538a19e1"
          "558e2fdaa56bd26ecba4c7342f28250f498cbc1075b181c762dd3afbdaa42f3267f7"
          "36faecdc81f49b1a4d2eaff96b635a505f1ae8b5210ca44fba8f1c0f2de96a38b35e"
          "64305d58c0be8f3cff0aa51f769139b6308b9ec4da6844709cda17d47cfa7deef634"
          "b8fa3215f2c38b1d3057cd3c"));
}

}  // namespace

std::vector<HybridTestVector> CreateHpkeTestVectors() {
  return {CreateTestVector0(),        CreateTestVector1(),
          CreateTestVector2(),        CreateTestVector3(),
          CreateTestVector4(),        CreateTestVector5(),
          CreateTestVectorXWing(),    CreateTestVectorMlKem768(),
          CreateTestVectorMlKem1024()};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
