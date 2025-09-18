// Copyright 2021 Google LLC
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

#include "tink/hybrid/internal/hpke_test_util.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1.
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
const absl::string_view kTestX25519HkdfSha256Aes128Gcm[] = {
    "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",  // pkRm
    "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83"
    "d07bea87e13c512a",                                                  // ct
    "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",  // skRm
    "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",  // enc
    "",                        // exporter_contexts[0]
    "00",                      // exporter_contexts[1]
    "54657374436f6e74657874",  // exporter_contexts[2]
    // exporter_values[0]
    "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee",
    // exporter_values[1]
    "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5",
    // exporter_values[2]
    "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931"};

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.2.
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
const absl::string_view kTestX25519HkdfSha256ChaCha20Poly1305[] = {
    "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",  // pkRm
    "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c"
    "62ce81883d2dd1b51a28",                                              // ct
    "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",  // skRm
    "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",  // enc
    "",                        // exporter_contexts[0]
    "00",                      // exporter_contexts[1]
    "54657374436f6e74657874",  // exporter_contexts[2]
    // exporter_values[0]
    "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e",
    // exporter_values[1]
    "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69",
    // exporter_values[2]
    "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"};

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.
// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
const absl::string_view kTestP256HkdfSha256Aes128Gcm[] = {
    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4c"
    "f969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",          // pkRm
    "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",  // ikmE
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e"
    "3ab2523f39513434",                                                  // ct
    "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",  // skRm
    "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b6"
    "1a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",  // enc
    "",                        // exporter_contexts[0]
    "00",                      // exporter_contexts[1]
    "54657374436f6e74657874",  // exporter_contexts[2]
    // exporter_values[0]
    "5e9bc3d236e1911d95e65b576a8a86d478fb827e8bdfe77b741b289890490d4d",
    // exporter_values[1]
    "6cff87658931bda83dc857e6353efe4987a201b849658d9b047aab4cf216e796",
    // exporter_values[2]
    "d8f1ea7942adbba7412c6d431c62d01371ea476b823eb697e1f6e6cae1dab85a"};

// Test vector from https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.5.
// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305
const absl::string_view kTestP256HkdfSha256ChaCha20Poly1305[] = {
    "04a697bffde9405c992883c5c439d6cc358170b51af72812333b015621dc0f40bad9bb726f"
    "68a5c013806a790ec716ab8669f84f6b694596c2987cf35baba2a006",          // pkRm
    "f1f1a3bc95416871539ecb51c3a8f0cf608afb40fbbe305c0a72819d35c33f1f",  // ikmE
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "6469c41c5c81d3aa85432531ecf6460ec945bde1eb428cb2fedf7a29f5a685b4ccb0d057f0"
    "3ea2952a27bb458b",                                                  // ct
    "a4d1c55836aa30f9b3fbb6ac98d338c877c2867dd3a77396d13f68d3ab150d3b",  // skRm
    "04c07836a0206e04e31d8ae99bfd549380b072a1b1b82e563c935c095827824fc1559eac6f"
    "b9e3c70cd3193968994e7fe9781aa103f5b50e934b5b2f387e381291",  // enc
    "",                        // exporter_contexts[0]
    "00",                      // exporter_contexts[1]
    "54657374436f6e74657874",  // exporter_contexts[2]
    // exporter_values[0]
    "9b13c510416ac977b553bf1741018809c246a695f45eff6d3b0356dbefe1e660",
    // exporter_values[1]
    "6c8b7be3a20a5684edecb4253619d9051ce8583baf850e0cb53c402bdcaf8ebb",
    // exporter_values[2]
    "477a50d804c7c51941f69b8e32fe8288386ee1a84905fe4938d58972f24ac938"};

// BoringSSL test vectors with aead_id = 2.  Missing 'skRm' and 'enc'.
// (No test vectors provided by RFC 9180 for this test case).
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
const absl::string_view kTestX25519HkdfSha256Aes256Gcm[] = {
    "ac66bae9ffa270cf4a89ed9f274e30c0456babae2572aaaf002ff0d8884ab018",  // pkRm
    "28e212563a8b6f068af7ff17400ff1baf23612b7a738bbaf5dfb321b2b5b431a",  // skEm
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "23ded2d5d90ea89d975dac4792b297240f194952d7421aacbff0474100052b6bb8aa58d1"
    "8ef6c42b6960e2e28f",  // ct
    "",                    // Missing skRm
    "",                    // Missing enc
    "",                    // Missing exporter_contexts[0]
    "",                    // Missing exporter_contexts[1]
    "",                    // Missing exporter_contexts[2]
    "",                    // Missing exporter_values[0]
    "",                    // Missing exporter_values[1]
    "",                    // Missing exporter_values[2]
};

// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM
const absl::string_view kTestP256HkdfSha256Aes256Gcm[] = {
    "04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f85314854"
    "4876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c",          // pkRm
    "a90d3417c3da9cb6c6ae19b4b5dd6cc9529a4cc24efb7ae0ace1f31887a8cd6c",  // ikmE
    "4f6465206f6e2061204772656369616e2055726e",                          // info
    "4265617574792069732074727574682c20747275746820626561757479",        // pt
    "436f756e742d30",                                                    // aad
    "58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd21"
    "6f8908da49f8f96f",  // ct
    "",                  // Missing skRm
    "",                  // Missing enc
    "",                  // Missing exporter_contexts[0]
    "",                  // Missing exporter_contexts[1]
    "",                  // Missing exporter_contexts[2]
    "",                  // Missing exporter_values[0]
    "",                  // Missing exporter_values[1]
    "",                  // Missing exporter_values[2]
};

// Test vector from BoringSSL (hpke_test_vectors.txt).
// X-Wing, HKDF-SHA256, AES-128-GCM
const absl::string_view kTestXWingHkdfSha256Aes128Gcm[] = {
    "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3da5"
    "fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b2a78"
    "5329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a5253401bacf"
    "a905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced40769923610034ae31"
    "e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef504"
    "1dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c3"
    "0869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea10463111c709f"
    "69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545eae13293460b3acb3"
    "7ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40b0501e1c753efe7305"
    "3c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c1055878240cad0f40d5f"
    "e3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362543c2517e4acd0e60ec071"
    "63009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635"
    "a4d7a67eb42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14fb"
    "d96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb333664ca4827"
    "63ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb4102cb7b2f9a25b2b4f061"
    "5de31decd9ca55026d6da0b65111b16fe52feed8a487e144462a6dba93728f500b6ffc49e5"
    "15569ef25fed17aff520507368253525860f58be3be61c964604a6ac814e6935596402a520"
    "a4670b3d284318866593d15a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96"
    "c5d7bf2b44bcf6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a"
    "8aad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499c61e138c"
    "21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364d6246d9f42cce53c66"
    "b59c45c8f9ae9299a75d15180c3c952151a91b7a10772429dc4cbae6fcc622fa8018c63439"
    "f890630b9928db6bb7f9438ae4065ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac"
    "35c06c000ce41a0582580e3bb57b672972890ac5e7988e7850657116f1b57d0809aaedec0b"
    "ede1ae148148311c6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be"
    "1c9692ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c"
    "8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71716094c964a68b"
    "03377f513a05bcd99c1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f"
    "3b9978b09d0e9c44d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda"
    "21b5a182b6da969e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7b"
    "cf4827ced611d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c2569"
    "14193ff7349042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69"
    "859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",  // pkRm
    "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df32347268600d40"
    "3fce431561aef583ee1613527cff655c1343f29812e66706df3234",      // skEm
    "4f6465206f6e2061204772656369616e2055726e",                    // info
    "4265617574792069732074727574682c20747275746820626561757479",  // pt
    "436f756e742d30",                                              // aad
    "a96ea59259a2893265d79052bfa8e976f6a9aaf9fb0cce901449f23c18a9e9b238e29161c2"
    "d94b5b6fefa046af",                                                  // ct
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",  // skRm
    "3829125bd65c4e3612e520ff3cd77938d11c7fa6445fe440a77ee7354b178b71018427144f"
    "b2ebcb0aab44f4456251d3885181e0bae0509793f7c160116630ecd898af82d557e5b8aa31"
    "3672c785e40a8c4b401ecc3d13300591933fe46f7061eaac318f4ab9277174c6282b2f1cc7"
    "b7c6dfe57e34f0a325732d58cce71a33fef826419f9c033e31001d8db456a4818563b07545"
    "30a855cde822c38643a73c19bb0a9552df2f36c9b00020b3a32d4130dd073ed9eddcea0463"
    "64bd25ca1ba99865e3aed169c338042fbd31dab9387ed9f5c6d6117bd320b6e3f7092fbab7"
    "e2ddceceb81907fcbea6986444836f86004e946ed1c0236dbc760fa06c1ec191d9c92b07e9"
    "0d243715975af3422980287fc7a57e120b604c8a598e8f1aac5d430e2b2801ff3b36da7640"
    "fdbc1fe41fc49fd04320ec86e9dc104aa88f7e346a950c0f2dc1c423fbde5adbd360b66079"
    "523795a9e351d17e5b2e943c6381b07c16612960aa682ddc7093e510a7f2b0f24761ab0564"
    "c926049dc330f3ed6c4ec23a6cf0f51fd99edae518fdb7615060931c3c0b58f34a7a8aa647"
    "368a8bed78ee7b5213bb730170320ccb218e42d7c06b4a5d9088acf3ea9d7f7633203e3a66"
    "372c2a75de396f329b6c0d35e2505dcb0ff2ec07eb5ca7f4f44a2d38df047aaeb5761e36fc"
    "65537a560ed302992aa03d0b0e20e96501e70545eafbc0bcb93e3d71761f814555c9407654"
    "0632509a23f2b19d632da32e86203a5232103e13707686e1c2662e50a5f3e08a730e90d400"
    "2aff2a85eda0b39c360e1618999100bc56d2c06e7c4cdd728f65a0e044ae2c0c94704b760b"
    "0d2a993483cc0636dcb7f5e1ff2453aee6804297b66b314d6158360a4f7f8dfaf70e83459a"
    "01b2a9b8e8e6b9dc69793b22940acae5ac404951358e7e31901b47ee6d12ee483e4d449bc8"
    "d59af6d56b982b4a6134e29648c54aa47e85d5eb63a98a94f53d91773bf63902057f096971"
    "9b28778881aa01504e3f8631b4091a19392bd1afe2554be79b6c61f125d78e16dec8dff31e"
    "778076ef81b4a30217b321fb714511e9d9fe87f6616572ec1b2d7dab2ed1eaab1bc8bd7f03"
    "3c2a95c6426b336a24a972a3efcdaf3614d3a570ec9bea43d2a1bcc9ca10590cd473acbdb0"
    "ba86d7b6a5d24a2a4b0b8b192846d2da9f6b7f6b43c7b6953ca071a47b7025dca6d452d196"
    "4106b8e640d6af37c87462e7bbd113cedbd336da61e283483624dd7551a4e62c8f4686e4e0"
    "01930ad8820962bedf2afbdd2f7cd5c79cd392e031671c349a92b4ee40271ce08cb0b83a76"
    "275a70dc56eca92a335f7584f7fa132171416b4eed2a8888edca372285fefbcfaf36646a7a"
    "45f95113f3015d190ebd7961f74960672fca13f96f8f076927baecfebc742443ff916b9331"
    "aa886718dd2a3a68703df5fb477b6d0942a55b6379e8920fede28bebdc36e7cbf56cb3d314"
    "3d1be5ddf7deac990fe41db417dc62f297f7956e20d6fa9d2a9735b5675c256fb3c94fff37"
    "bafa16fa15e299ba47a311263f9581298172eafc6e007b6cb01a54e73f5c4bc692d5e002e9"
    "b423301a39155577991d",    // enc
    "",                        // exporter_contexts[0]
    "00",                      // exporter_contexts[1]
    "54657374436f6e74657874",  // exporter_contexts[2]
    // exporter_values[0]
    "c78ebc7a3064b7274dd5c316d62bb05114a7578b0af79cd856a38d6bcdde72a9",
    // exporter_values[1]
    "a5d3e6562b1d9cf928620d51a1d5c141045e0ab91af77d2b5d4f9cf9d85813d9",
    // exporter_values[2]
    "5fd0d16475885903b6c533a789e2dbe1f8a6088b8424534f9b0922314dd2ae4e"};

HpkeTestParams DefaultHpkeTestParams() {
  return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
}

absl::StatusOr<HpkeTestParams> CreateHpkeTestParams(
    const google::crypto::tink::HpkeParams& proto_params) {
  HpkeParams params;

  switch (proto_params.kem()) {
    case google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256:
      params.kem = HpkeKem::kP256HkdfSha256;
      break;
    case google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256:
      params.kem = HpkeKem::kX25519HkdfSha256;
      break;
    case google::crypto::tink::HpkeKem::X_WING:
      params.kem = HpkeKem::kXWing;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified KEM:",
                                       proto_params.kem()));
  }

  switch (proto_params.kdf()) {
    case google::crypto::tink::HpkeKdf::HKDF_SHA256:
      params.kdf = HpkeKdf::kHkdfSha256;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified KDF:",
                                       proto_params.kdf()));
  }

  switch (proto_params.aead()) {
    case google::crypto::tink::HpkeAead::AES_128_GCM:
      params.aead = HpkeAead::kAes128Gcm;
      break;
    case google::crypto::tink::HpkeAead::AES_256_GCM:
      params.aead = HpkeAead::kAes256Gcm;
      break;
    case google::crypto::tink::HpkeAead::CHACHA20_POLY1305:
      params.aead = HpkeAead::kChaCha20Poly1305;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified AEAD:",
                                       proto_params.aead()));
  }
  return CreateHpkeTestParams(params);
}

absl::StatusOr<HpkeTestParams> CreateHpkeTestParams(const HpkeParams& params) {
  if (params.kdf != HpkeKdf::kHkdfSha256) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KDF:", params.kdf));
  }
  if (params.kem == HpkeKem::kP256HkdfSha256) {
    switch (params.aead) {
      case HpkeAead::kAes128Gcm:
        return HpkeTestParams(kTestP256HkdfSha256Aes128Gcm);
      case HpkeAead::kAes256Gcm:
        return HpkeTestParams(kTestP256HkdfSha256Aes256Gcm);
      case HpkeAead::kChaCha20Poly1305:
        return HpkeTestParams(kTestP256HkdfSha256ChaCha20Poly1305);
      default:
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("No test parameters for specified AEAD:",
                         params.aead));
    }
  } else if (params.kem == HpkeKem::kX25519HkdfSha256) {
    switch (params.aead) {
      case HpkeAead::kAes128Gcm:
        return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
      case HpkeAead::kAes256Gcm:
        return HpkeTestParams(kTestX25519HkdfSha256Aes256Gcm);
      case HpkeAead::kChaCha20Poly1305:
        return HpkeTestParams(kTestX25519HkdfSha256ChaCha20Poly1305);
      default:
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("No test parameters for specified AEAD:",
                         params.aead));
    }
  } else if (params.kem == HpkeKem::kXWing) {
    switch (params.aead) {
      case HpkeAead::kAes128Gcm:
        return HpkeTestParams(kTestXWingHkdfSha256Aes128Gcm);
      default:
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("No test parameters for specified AEAD:",
                         params.aead));
    }
  } else {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No test parameters for specified KEM:", params.kem));
  }
}

google::crypto::tink::HpkeParams CreateHpkeParams(
    const google::crypto::tink::HpkeKem& kem,
    const google::crypto::tink::HpkeKdf& kdf,
    const google::crypto::tink::HpkeAead& aead) {
  google::crypto::tink::HpkeParams params;
  params.set_kem(kem);
  params.set_kdf(kdf);
  params.set_aead(aead);
  return params;
}

google::crypto::tink::HpkePublicKey CreateHpkePublicKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes) {
  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(raw_key_bytes);
  *key_proto.mutable_params() = params;
  return key_proto;
}

google::crypto::tink::HpkePrivateKey CreateHpkePrivateKey(
    const google::crypto::tink::HpkeParams& params,
    const std::string& raw_key_bytes) {
  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_private_key(raw_key_bytes);
  google::crypto::tink::HpkePublicKey* public_key_proto =
      private_key_proto.mutable_public_key();
  *public_key_proto->mutable_params() = params;
  return private_key_proto;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
