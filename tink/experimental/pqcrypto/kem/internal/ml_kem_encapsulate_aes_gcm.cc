// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_aes_gcm.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mlkem.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_raw_encapsulate_boringssl.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/internal/raw_kem_encapsulate.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/partial_key_access.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlKemEncapsulateAes256Gcm : public KemEncapsulate {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  static util::StatusOr<std::unique_ptr<KemEncapsulate>> New(
      MlKemPublicKey recipient_key, AesGcmParameters aes_gcm_parameters);

  explicit MlKemEncapsulateAes256Gcm(
      std::unique_ptr<RawKemEncapsulate> raw_kem_encapsulate,
      AesGcmParameters aes_gcm_parameters)
      : raw_kem_encapsulate_(std::move(raw_kem_encapsulate)),
        aes_gcm_parameters_(std::move(aes_gcm_parameters)) {}

  util::StatusOr<KemEncapsulation> Encapsulate() const override;

 private:
  std::unique_ptr<RawKemEncapsulate> raw_kem_encapsulate_;
  AesGcmParameters aes_gcm_parameters_;
};

util::StatusOr<std::unique_ptr<KemEncapsulate>> MlKemEncapsulateAes256Gcm::New(
    MlKemPublicKey recipient_key, AesGcmParameters aes_gcm_parameters) {
  util::Status status = CheckFipsCompatibility<MlKemEncapsulateAes256Gcm>();
  if (!status.ok()) {
    return status;
  }

  if (aes_gcm_parameters.KeySizeInBytes() != MLKEM_SHARED_SECRET_BYTES) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("AES-GCM parameters are not compatible with ML-KEM: the "
                     "ML-KEM shared secret is ",
                     MLKEM_SHARED_SECRET_BYTES,
                     " bytes but the AES key size is ",
                     aes_gcm_parameters.KeySizeInBytes(), " bytes"));
  }

  if (aes_gcm_parameters.HasIdRequirement()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Keys derived from an ML-KEM shared secret must not "
                        "have an ID requirement");
  }

  util::StatusOr<std::unique_ptr<RawKemEncapsulate>> raw_kem_encapsulate =
      NewMlKemRawEncapsulateBoringSsl(std::move(recipient_key));
  if (!raw_kem_encapsulate.ok()) {
    return raw_kem_encapsulate.status();
  }

  return absl::make_unique<MlKemEncapsulateAes256Gcm>(
      *std::move(raw_kem_encapsulate), std::move(aes_gcm_parameters));
}

util::StatusOr<KemEncapsulation> MlKemEncapsulateAes256Gcm::Encapsulate()
    const {
  util::StatusOr<RawKemEncapsulation> raw_kem_encapsulation =
      raw_kem_encapsulate_->Encapsulate();
  if (!raw_kem_encapsulation.ok()) {
    return raw_kem_encapsulation.status();
  }

  util::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      aes_gcm_parameters_, raw_kem_encapsulation->shared_secret,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      absl::make_unique<AesGcmKey>(*key), KeyStatus::kEnabled,
      /*is_primary=*/true);
  util::StatusOr<KeysetHandle> keyset_handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  if (!keyset_handle.ok()) {
    return keyset_handle.status();
  }

  KemEncapsulation kem_encapsulation;
  kem_encapsulation.ciphertext = raw_kem_encapsulation->ciphertext;
  kem_encapsulation.keyset_handle = *keyset_handle;
  return kem_encapsulation;
}

}  // namespace

util::StatusOr<std::unique_ptr<KemEncapsulate>> NewMlKemEncapsulateAes256Gcm(
    MlKemPublicKey recipient_key, AesGcmParameters aes_gcm_parameters) {
  return MlKemEncapsulateAes256Gcm::New(std::move(recipient_key),
                                        std::move(aes_gcm_parameters));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
