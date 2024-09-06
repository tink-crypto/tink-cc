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
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
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

HpkeTestParams DefaultHpkeTestParams() {
  return HpkeTestParams(kTestX25519HkdfSha256Aes128Gcm);
}

util::StatusOr<HpkeTestParams> CreateHpkeTestParams(
    const google::crypto::tink::HpkeParams& proto_params) {
  HpkeParams params;

  switch (proto_params.kem()) {
    case google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256:
      params.kem = HpkeKem::kP256HkdfSha256;
      break;
    case google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256:
      params.kem = HpkeKem::kX25519HkdfSha256;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified KEM:",
                                       proto_params.kem()));
  }

  switch (proto_params.kdf()) {
    case google::crypto::tink::HpkeKdf::HKDF_SHA256:
      params.kdf = HpkeKdf::kHkdfSha256;
      break;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
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
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("No test parameters for specified AEAD:",
                                       proto_params.aead()));
  }
  return CreateHpkeTestParams(params);
}

util::StatusOr<HpkeTestParams> CreateHpkeTestParams(const HpkeParams& params) {
  if (params.kdf != HpkeKdf::kHkdfSha256) {
    return util::Status(
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
        return util::Status(
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
        return util::Status(
            absl::StatusCode::kInvalidArgument,
            absl::StrCat("No test parameters for specified AEAD:",
                         params.aead));
    }
  } else {
    return util::Status(
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
