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

#include "tink/hybrid/internal/hpke_util_boringssl.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<const EVP_HPKE_KEM*> KemParam(const HpkeParams& params) {
  switch (params.kem) {
    case HpkeKem::kP256HkdfSha256:
      return EVP_hpke_p256_hkdf_sha256();
    case HpkeKem::kX25519HkdfSha256:
      return EVP_hpke_x25519_hkdf_sha256();
    case HpkeKem::kXWing:
      return EVP_hpke_xwing();
    case HpkeKem::kMlKem768:
      return EVP_hpke_mlkem768();
    case HpkeKem::kMlKem1024:
      return EVP_hpke_mlkem1024();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE KEM algorithm: ", params.kem));
  }
}

absl::StatusOr<const EVP_HPKE_KEM*> KemParam(
    const google::crypto::tink::HpkeKem& kem) {
  switch (kem) {
    case google::crypto::tink::HpkeKem::DHKEM_P256_HKDF_SHA256:
      return EVP_hpke_p256_hkdf_sha256();
    case google::crypto::tink::HpkeKem::DHKEM_X25519_HKDF_SHA256:
      return EVP_hpke_x25519_hkdf_sha256();
    case google::crypto::tink::HpkeKem::X_WING:
      return EVP_hpke_xwing();
    case google::crypto::tink::HpkeKem::ML_KEM768:
      return EVP_hpke_mlkem768();
    case google::crypto::tink::HpkeKem::ML_KEM1024:
      return EVP_hpke_mlkem1024();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE KEM algorithm: ", kem));
  }
}

absl::StatusOr<const EVP_HPKE_KEM*> KemParam(
    const google::crypto::tink::HpkeParams& params) {
  return KemParam(params.kem());
}

absl::StatusOr<const EVP_HPKE_KDF*> KdfParam(const HpkeParams& params) {
  switch (params.kdf) {
    case HpkeKdf::kHkdfSha256:
      return EVP_hpke_hkdf_sha256();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE KDF algorithm: ", params.kdf));
  }
}

absl::StatusOr<const EVP_HPKE_KDF*> KdfParam(
    const google::crypto::tink::HpkeParams& params) {
  switch (params.kdf()) {
    case google::crypto::tink::HpkeKdf::HKDF_SHA256:
      return EVP_hpke_hkdf_sha256();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE KDF algorithm: ", params.kdf()));
  }
}

absl::StatusOr<const EVP_HPKE_AEAD*> AeadParam(const HpkeParams& params) {
  switch (params.aead) {
    case HpkeAead::kAes128Gcm:
      return EVP_hpke_aes_128_gcm();
    case HpkeAead::kAes256Gcm:
      return EVP_hpke_aes_256_gcm();
    case HpkeAead::kChaCha20Poly1305:
      return EVP_hpke_chacha20_poly1305();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE AEAD algorithm: ", params.aead));
  }
}

absl::StatusOr<const EVP_HPKE_AEAD*> AeadParam(
    const google::crypto::tink::HpkeParams& params) {
  switch (params.aead()) {
    case google::crypto::tink::HpkeAead::AES_128_GCM:
      return EVP_hpke_aes_128_gcm();
    case google::crypto::tink::HpkeAead::AES_256_GCM:
      return EVP_hpke_aes_256_gcm();
    case google::crypto::tink::HpkeAead::CHACHA20_POLY1305:
      return EVP_hpke_chacha20_poly1305();
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported HPKE AEAD algorithm: ", params.aead()));
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
