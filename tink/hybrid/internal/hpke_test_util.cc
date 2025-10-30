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

// Test vector from BoringSSL (hpke_test_vectors.txt).
// ML-KEM-768, HKDF-SHA256, AES-128-GCM
const absl::string_view kTestMlKem768HkdfSha256Aes128Gcm[] = {
    "a8e651a1e685f22478a8954f007bc7711b930772c78f092e82878e3e937f367967532913a8"
    "d53dfdf4bfb1f8846746596705cf345142b972a3f16325c40c2952a37b25897e5ef35fbaeb"
    "73a4acbeb6a0b89942ceb195531cfc0a07993954483e6cbc87c06aa74ff0cac5207e535b26"
    "0aa98d1198c07da605c4d11020f6c9f7bb68bb3456c73a01b710bc99d17739a51716aa0166"
    "0c8b628b2f5602ba65f07ea993336e896e83f2c5731bbf03460c5b6c8afecb748ee391e989"
    "34a2c57d4d069f50d88b30d6966f38c37bc649b82634ce7722645ccd625063364646d6d699"
    "db57b45eb67465e16de4d406a818b9eae1ca916a2594489708a43cea88b02a4c03d09b4481"
    "5c97101caf5048bbcb247ae2366cdc254ba22129f45b3b0eb399ca91a303402830ec01db7b"
    "2ca480cf350409b216094b7b0c3ae33ce10a9124e89651ab901ea253c8415bd7825f02bb22"
    "9369af972028f22875ea55af16d3bc69f70c2ee8b75f28b47dd391f989ade314729c331fa0"
    "4c1917b278c3eb602868512821adc825c64577ce1e63b1d9644a612948a3483c7f1b9a2580"
    "00e30196944a403627609c76c7ea6b5de01764d24379117b9ea29848dc555c454bceae1ba5"
    "cc72c74ab96b9c91b910d26b88b25639d4778ae26c7c6151a19c6cd7938454372465e4c5ec"
    "29245acb3db5379de3dabfa629a7c04a8353a8530c95acb732bb4bb81932bb2ca7a848cd36"
    "6801444abe23c83b366a87d6a3cf360924c002bae90af65c48060b3752f2badf1ab2722072"
    "554a5059753594e6a702761fc97684c8c4a7540a6b07fbc9de87c974aa8809d928c7f4cbbf"
    "8045aea5bc667825fd05a521f1a4bf539210c7113bc37b3e58b0cbfc53c841cbb0371de2e5"
    "11b989cb7c70c023366d78f9c37ef047f8720be1c759a8d96b93f65a94114ffaf60d9a8179"
    "5e995c71152a4691a5a602a9e1f3599e37c768c7bc108994c0669f3adc957d46b4b6256968"
    "e290d7892ea85464ee7a750f39c5e3152c2dfc56d8b0c924ba8a959a68096547f66423c838"
    "982a5794b9e1533771331a9a656c28828beb9126a60e95e8c5d906832c7710705576b1fb95"
    "07269ddaf8c95ce9719b2ca8dd112be10bcc9f4a37bd1b1eeeb33ecda76ae9f69a5d4b2923"
    "a86957671d619335be1c4c2c77ce87c41f98a8cc466460fa300aaf5b301f0a1d09c88e65da"
    "4d8ee64f68c02189bbb3584baff716c85db654048a004333489393a07427cd3e217e6a345f"
    "6c2c2b13c27b337271c0b27b2dbaa00d237600b5b594e8cf2dd625ea76cf0ed899122c9796"
    "b4b0187004258049a477cd11d68c49b9a0e7b00bce8cac7864cbb375140084744c93062694"
    "ca795c4f40e7acc9c5a1884072d8c38dafb501ee4184dd5a819ec24ec1651261f962b17a72"
    "15aa4a748c15836c389137678204838d7195a85b4f98a1b574c4cd7909cd1f833effd14855"
    "43229d3748d9b5cd6c17b9b3b84aef8bce13e683733659c79542d615782a71cdeee792bab5"
    "1bdc4bbfe8308e663144ede8491830ad98b4634f64aba8b9c042272653920f380c1a17ca87"
    "ced7aac41c82888793181a6f76e197b7b90ef90943bb3844912911d8551e5466c5767ab0bc"
    "61a1a3f736162ec098a900b12dd8fabbfb3fe8cb1dc4e8315f2af0d32f0017ae136e19f02"
    "8",                                                                 // pkRm
    "147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615",  // skEm
    "b254a656608933b934b3f81e8f810214c8135eda92a0614c2b926c4a3075b9f939e6a3c613"
    "09f53e",  // info
    "86526d8f8d975a50785055b1f6120e6e76e1088730919310d486016a1c62b9a797c5f8842c"
    "16260f959c1620d43632975a6c3f309b6891398c8c5a4d31481180de",  // pt
    "c7a312a03e4b00",                                            // aad
    "098a79728a9e35e661db9e25c80ca6dd0443730194d42d6848f09268c864a8d1c6d67bc7d7"
    "3efc7fece9b312ea2ea0017df500c66968fa882c6e3d4648f0fed32899b40e046c96001186"
    "1824b6fab3056a",  // ct
    "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d4"
    "51140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f",  // skRm
    "c8391085b8d3ea9794212541b2914f08964d33521d3f67ad66096ebfb1f706424b49558f75"
    "5b5625bae236f2e0079601c766f7d960808f7e2bb0c7a5e066ed346de628f8c57eebabbb0c"
    "22d911548463693ef3ce52a53f7ff415f00e657ae1c5a48fa5ec6e4be5cf462daffc84d2f6"
    "d5ff55dc9bbe8bb0d725ec64fd4cd4bd8dba0a844e8b5ce4b6a28934d7f7a050991fe185b5"
    "06b451dabfad52d52cb2114ca7d9a5cf986c8fdc1bc10ec0c1869e50c03c55a76192a1049a"
    "ca636ba9020bdaa8d0f58c763b0b89845ca06d4c4ddc21433e16b9c62e44871fdbc05ba218"
    "af871fdd7dcfa464e60faa5265264ce1391bd9a8c5faa7626d5f159b9805b975710a3503a0"
    "b858a11c6a647cc0e19ac88b1be9056c95b4d2087d0951d1d2f4992491117e6347794ba545"
    "71ec49bba71af3413d38a30bf5872248d1f6d07c86baf782e73d2637f043d341a00921857d"
    "8b21ddf3e1d6310036ed27af49e5de1b900fe4de79808ff29f9570859612b15adc01fbb265"
    "b305b1e3a12ae419da5b74261fa284c101da3d8dca8b2e4521aca571ef44a058e844ff32b1"
    "6d5aaea05f7f3af8e2ab16222e347662eddfb891d0ecc2a55c5638f9dde92d9a3d544a5f90"
    "1ac501acd1ea6a010201fcb10ad702c425a94bdf5890d500a2a147eee1d1fcba8c3abe7c2d"
    "fe70f346f033d816a0b2791b4f0b2d956d9ee5971715399a5688302495e2e07c1c8c015271"
    "84bcd0c208bc159f2e13318c0bb3dd24a6a7fc849f83385ed4dba07fe1d7bd5640cc9ed5cc"
    "fdd68763cb0d0edf61b292177fc1d2d3c11dd0495056bcb12558aebcfddef9feb4aebc57af"
    "d9023c65cfe65a24e33f1b00111e92e63e011eaf0b212cf95743cd07f5189ece1f205b7f6f"
    "cb2e6b1961b5404cebe47c8cd13b8599d5b49e6d87eeda36e9b8fc4c00635896aa2b75896e"
    "336d1b612ee13db811e1f07e61748d920f4865f3f11741399dc6162c91ca168a02329dff82"
    "1d58198712dd558abb099b3a0baf9da1b730b2aa73bcf58d74f357b06f7211c804b6c8af16"
    "ff3509fad1d35b14bfdced7db8a6a25c48e5956480724daa057cd660b67ee3e47257418267"
    "9d485838a6476eac02141075c812af7967ba7c9185cc2abd2a4545b80f3d3104d58d654a57"
    "792dcfabbe9c0715e8de2ef81ef404c8168fd7a43efab3d448e686a088efd26a2615994892"
    "6723d7eccc39e3c1b719cf8becb7be7e964f22cd8cb1b7e25e800ea97d60a64cc0bbd9cb40"
    "7a3ab9f88f5e29169eeafd4e0322fde6590ae093ce8feeae98b622caa7556ff426c9e7a404"
    "ce69355830a7a67767a76c7d9a97b84bfcf50a02f75c235d2f9c671138049ffc7c8055926c"
    "03eb3fb87f9695185a42eca9a41655873d30a6b3bf428b246223484a8ff61ee3eeafff10e9"
    "9c2c13a76284d063e56ab711a35a85b5383df81da23490f66e8ea3fcba067f5530c6541c2b"
    "8f74717c35023e7b9b3956c3ee2ff84ba03ccf4b4b5321b9240895481bc6d63c1693c18478"
    "52f8e97f50a133532ac3ee1e52d464",  // enc
    "e6b783f915c4d02e19a8b13e30",      // exporter_contexts[0]
    "e6b783f915c4d02e19a8b13e31",      // exporter_contexts[1]
    "e6b783f915c4d02e19a8b13e32",      // exporter_contexts[2]
    // exporter_values[0]
    "a6c6493b83c0b91b2f9c4d8566e37b6056e5eecf12a48f77fda8236299ce5024",
    // exporter_values[1]
    "2faede908e025d8d4c842b83cde5051e2dfcd2ee41b320ff951ec6ce3b1ef754",
    // exporter_values[2]
    "4677efc20345ac8197ac0ba21d6c7bf148b8fa79ee310eab6008143e81fce4a4"};

// Test vector from BoringSSL (hpke_test_vectors.txt).
// ML-KEM-1024, HKDF-SHA256, AES-256-GCM
const absl::string_view kTestMlKem1024HkdfSha256Aes256Gcm[] = {
    "537911957c125148a87f41589cb222d0d19229e2cb55e1a044791e7ca61192a46460c3183d"
    "2bcd6de08a5e7651603acc349ca16cba18abb23a3e8c330d7421598a6278ec7ebfabca0ef4"
    "88b2290554753499c0452e453815309955b8150fa1a1e393386dc12fdb27b38c6745f29440"
    "16ec457f39b18d604a07a1abe07bc844050ffa8a06fa154a49d88fac775452d6a7c0e589bf"
    "b5c370c2c4b6201dda80c9ab2076ecc08b44522fda3326f033806dd2693f319739f40c4f42"
    "b24aca7098fb8ff5f9ac20292d02b56ac746801acccc84863dee32878497b69438bf991776"
    "286650482c8d9d9587bc6a55b85c4d7fa74d02656b421c9e23e03a48d4b74425c26e4a20dd"
    "9562a4da0793f3a352ccc0f18217d868c7f5002abe768b1fc73f05744e7cc28f10344062c1"
    "0e08eccced3c1f7d392c01d979dd718d8398374665a16a9870585c39d5589a50e133389c9b"
    "9a276c024260d9fc7711c81b6337b57da3c376d0cd74e14c73727b276656b9d8a4eb71896f"
    "f589d4b893e7110f3bb948ece291dd86c0b7468a678c746980c12aa6b95e2b0cbe4331bb24"
    "a33a270153aa472c47312382ca365c5f35259d025746fc6595fe636c767510a69c1e8a176b"
    "7949958f2697399497a2fc7364a12c8198295239c826cb5082086077282ed628651fc04c63"
    "9b438522a9de309b14b086d6e923c551623bd72a733cb0dabc54a9416a99e72c9fda1cb3fb"
    "9ba06b8adb2422d68cadc553c98202a17656478ac044ef3456378abce9991e0141ba79094f"
    "a8f77a300805d2d32ffc62bf0ca4554c330c2bb7042db35102f68b1a0062583865381c74dd"
    "913af70b26cf0923d0c4cb971692222552a8f4b788b4afd1341a9df415cf203900f5ccf7f6"
    "5988949a75580d049639853100854b21f4018003502bb1ba95f556a5d67c7eb52410eba288"
    "a6d0635ca8a4f6d696d0a020c826938d34943c3808c79cc007768533216bc1b29da6c812ef"
    "f3340baa8d2e65344f09bd47894f5a3a4118715b3c5020679327f9189f7e10856b238bb9b0"
    "ab4ca85abf4b21f5c76bccd71850b22e045928276a0f2e951db0707c6a116dc19113fa762d"
    "c5f20bd5d2ab5be71744dc9cbdb51ea757963aac56a90a0d8023bed1f5cae8a64da047279b"
    "353a096a835b0b2b023b6aa048989233079aeb467e522fa27a5822921e5c551b4f537536e4"
    "6f3a6a97e72c3b063104e09a040598940d872f6d871f5ef9b4355073b54769e45454e6a081"
    "9599408621ab4413b35507b0df578ce2d511d52058d5749df38b29d6cc58870caf92f69a75"
    "161406e71c5ff92451a77522b8b2967a2d58a49a81661aa65ac09b08c9fe45abc3851f99c7"
    "30c45003aca2bf0f8424a19b7408a537d541c16f5682bfe3a7faea564f1298611a7f5f6092"
    "2ba19de73b1917f1853273555199a649318b50773345c997460856972acb43fc81ab6321b1"
    "c33c2bb5098bd489d696a0f70679c1213873d08bdad42844927216047205633212310ee9a0"
    "6cb10016c805503c341a36d87e56072eabe23731e34af7e2328f85cdb370ccaf00515b64c9"
    "c54bc837578447aacfaed5969aa351e7da4efa7b115c4c51f4a699779850295ca72d781ad4"
    "1bc680532b89e710e2189eb3c50817ba255c7474c95ca9110cc43b8ba8e682c7fb7b0fdc26"
    "5c0483a65ca4514ee4b832aac5800c3b08e74f563951c1fbb210353efa1aa866856bc1e034"
    "733b0485dab1d020c6bf765ff60b3b801984a90c2fe970bf1de97004a6cf44b4984ab58258"
    "b4af71221cd17530a700c32959c9436344b5316f09ccca7029a230d639dcb022d8ba79ba91"
    "cd6ab12ae1579c50c7bb10e30301a65cae3101d40c7ba927bb553148d1647024d4a06c8166"
    "d0b0b81269b7d5f4b34fb022f69152f514004a7c685368552343bb60360fbb9945edf446d3"
    "45bdcaa7455c74ba0a551e184620fef97688773d50b6433ca7a7ac5cb6b7f671a15376e5a6"
    "747a623fa7bc6630373f5b1b512690a661377870a60a7a189683f9b0cf0466e1f750762631"
    "c4ab09f505c42dd28633569472735442851e321616d4009810777b6bd46fa7224461a5cc27"
    "405dfbac0d39b002cab33433f2a86eb8ce91c134a6386f860a1994eb4b6875a46d195581d1"
    "73854b53d2293df3e9a822756cd8f212b325ca29b4f9f8cfbadf2e41869abfbad10738ad04"
    "cc752bc20c394746850e0c4847db",                                      // pkRm
    "147c03f7a5bebba406c8fae1874d7f13c80efe79a3a9a874cc09fe76f6997615",  // skEm
    "b9e8c67f3a2d1e0c4b59f7d6a5c3b2e18d9f0a786e5c4d3b2a1f0987e6d5c4b3",  // info
    "c8a4153f9b7e2d06c5478f1a3e6d9c0b25748f3e9a6c1b4d8e7f5a2b0d9e8c1f7a4b6d3e9f"
    "2a7c5b8e1d4f0a3c7b8e2d5f1a4c9b8d2e6f3a7c1b5d9e",  // pt
    "d35b1f8a9e4c20",                                  // aad
    "ac74bab5b38ff861ae142eadd79fae5413fcabade436df3b12556feb766c3e14c45bdefddb"
    "0914dc2f7f243e5bcf4665dea93cc6c5d808e6a582465cc0a4b06d06217093b2b13896bc9c"
    "f2f8",  // ct
    "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d8626ed79d4"
    "51140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f",  // skRm
    "c9bead6b0c1114389bd4761c73ab9095b5809daac9f659bb564af226173052a4a3e7f2e5fd"
    "47d2b02aaeb5189e06b9f4ae98b619cb63efbdf3989a94b36e8ea0d700633b950a0ae2a78e"
    "d92e85c85c70e13e626fb263fac9681521c3ab22fdab29173c9616a2b037083ff7b2e019b5"
    "bcde068fac257ef8f12798411693c1bdcc65420997a513a8a69502620be8e4ce7362e412a7"
    "6cf51c1f2433f1ab64ce0e5d2f56d7c9ade994d0e35d0aeef3ac515b482437664d8c1d25e5"
    "a5507cf80f970d3ea7226aacdc457cbf88a0560aa35bb2c5c455867e2159910a35810befe3"
    "aa10eb04d8d57147cb8f66d2b070bac43d1f1ffdd57a9399951f64965727bcb9f66ad42309"
    "dafc799c1c540af1af93eff68a86d61f5115db662dee7ac9a362677762b6a164a0fa0a4d85"
    "9e4b8c8dbdb4e183f5e6808fc52229650caf7cf3e16de3d895d148c35448ab8c2753c9831b"
    "24bd4921497eaa192565cabfd83c0c68dfe7d392abf5e5e6f84bb9f5af4b7118c0b558105f"
    "9c10c9b6d70682e1de6e0689d7106a6374bd34aed7229e6cb356f2ea65e680ce7b1e2c3704"
    "e116a38542826e8a001141baf2e34de37a03040986d4c0cd5d57f0701ce930986fd9525b58"
    "e2e59f45b8dd04c0f35b0f47970cc67079618eb9e6d91e9b0f8c6d2e165cf448a2c1ebf71b"
    "6537e0f375185dfafef698b6239bb35580b315bcb5ed408c357f192def89bc1b75cdd6aae8"
    "b5faf0c3e13803f6bdfa76fb407fcbda790c329b3ee42fd3d3b03bd5003f0bc432f7ba3963"
    "1112452dfd12140433ff8980eb6a526ba85ef99477378b4dc76635a5cd5040e43b8c1fe4ee"
    "5e158e423bfc0c893c1d5613bed08da719c9073184eeb36fd357380fb1873d8cbd36e2255e"
    "985b1b76819743a6584a9b3a580996c9c2eed9bbbfff78a6204b5e5eeae5f4efd2660078b3"
    "7f0754ab5da862e666b145b5f23f3d0977799929dfa2aedda53d152eda1d0d0e4ea43f6ed8"
    "89bb965eefe0a7c685bb36770eaa874242c0e229cf6ce56defa5aeae64d0c40dda8aa26eae"
    "b31458f070a3bc72e1619ee9b5f642291c56df5b7e43db6c802fc74f4f3f9b5c0d355c3aae"
    "520aa31229d12f3e7cc5d48e691191a36b283765f4133f0ff1fe2f01c6648b2798a74eb5d8"
    "42a248f524a7e7f8974211297b44f0dd19f386e86be6ba782de77fde887226f37a1c77bc5e"
    "ddeee5bf46b67fb7478d559865f262caa84d64a8ce59e4df0818e14861526acd3483600f3d"
    "ae7959d35d8181ca6a81ce791be00752da7759446a2cfbe00b8248b93491debd520220b755"
    "416d2fc6b7c8af2ff75e5bcbb8e7537380a5721c77484957a69271d8bafce0f166735ff869"
    "232de5d381afbf0e44d69172b79a35191949de09703b94222b13c385c6081e6d2ede1e57fe"
    "184ef8f60196b9a3a7b7eff7497191ca8741b5a01e79cb69a61142e6f5d080fbb3e566f79e"
    "146f75c8a1097860841b4747df604dba954e4a8d9e0dccc1f609d05cf8d31219ecd60c312d"
    "e684552f09227cb829291c645732c5f5d4d711639f42a23080aa34fe1420f219bd6bcf4e3b"
    "29b9d02293b2da81383e0a51d2bb186c7b0a211a0cd63acbfc0210401e985d436b3803d560"
    "1c24136afd1562522e45b457cb439178be4a87cce40346d34ae0f3c39103c8a3ebc9c86c8d"
    "b8fc5561eb0f3a143d4e9fe93a5cba6f6fcae5650d3f43d2668a5956c922893b816647ded0"
    "afc052a6c3d9d01a3d3af0f1ba807ff10491e131dc15e165cfd0650a1f2c313d7956141edc"
    "c61cb90e9e7abf2fe35fc9dc1bde88939fa11f7bbe3eb4d8ffa643b074d74f45113586e9bb"
    "12060003d71941f2da098dc0e96cad3255cf328ea2d3308c1f4585e89c613c426b7e798e1e"
    "c4e98fe6c71e7491f5eca0cd05115861bd160e3fe73a58a026ba538e0e256b92f1d7a24975"
    "70594856860ffd06b601ac575592f4ac612b5de7866042123ebc60c55768e3a7600a326055"
    "1f2bea22bbf6b6c8246e80f9125c4bb9db354dd64ae695c15f5071f4abb9639207cac7331b"
    "310f69a05f54b995de529a023f033b055db95287a14ba30a7cc526bb724c417fba290636a9"
    "96f286e3e9e939e4fe1c398b5c6599959d0b4445a327ec469a1653cfaea7552cecec085cca"
    "a68938ae4ac3c424f7e480439ebd2c992b5f6f95ec244b657dbdeaa9ae110aaf4d68bf4e27"
    "410d43ceef3e88e9c717dd44c9ee",  // enc
    "b8f4e2d7c06399b8a4fde25c20",    // exporter_contexts[0]
    "b8f4e2d7c06399b8a4fde25c21",    // exporter_contexts[1]
    "b8f4e2d7c06399b8a4fde25c22",    // exporter_contexts[2]
    // exporter_values[0]
    "e166fafd5983c1195a476ce1c78a731e5f958ac07d256a74fe4f75c729b8fb43",
    // exporter_values[1]
    "00df22113c678fddebe28ab48c5a769b2dfa0ecf8ae67c1cae1223c016995e3b",
    // exporter_values[2]
    "2f9183c7b2cedd7fe17c54b3209c44ac4424d821b049fdca1c27027abc1e9f62"};

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
    case google::crypto::tink::HpkeKem::ML_KEM768:
      params.kem = HpkeKem::kMlKem768;
      break;
    case google::crypto::tink::HpkeKem::ML_KEM1024:
      params.kem = HpkeKem::kMlKem1024;
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
  } else if (params.kem == HpkeKem::kMlKem768) {
    switch (params.aead) {
      case HpkeAead::kAes128Gcm:
        return HpkeTestParams(kTestMlKem768HkdfSha256Aes128Gcm);
      default:
        return absl::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("No test parameters for specified AEAD:",
                         params.aead));
    }
  } else if (params.kem == HpkeKem::kMlKem1024) {
    switch (params.aead) {
      case HpkeAead::kAes256Gcm:
        return HpkeTestParams(kTestMlKem1024HkdfSha256Aes256Gcm);
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
