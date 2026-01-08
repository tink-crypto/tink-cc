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

#include "tink/hybrid/internal/hpke_decrypt.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/internal/hpke_context.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid_decrypt.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::HpkePrivateKey;
using HpkeAeadProto = ::google::crypto::tink::HpkeAead;
using HpkeKdfProto = ::google::crypto::tink::HpkeKdf;
using HpkeKemProto = ::google::crypto::tink::HpkeKem;
using HpkeParamsProto = ::google::crypto::tink::HpkeParams;
using HpkePrivateKeyProto = ::google::crypto::tink::HpkePrivateKey;

absl::StatusOr<HpkeKemProto> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKemProto::DHKEM_P256_HKDF_SHA256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKemProto::DHKEM_P384_HKDF_SHA384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKemProto::DHKEM_P521_HKDF_SHA512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKemProto::DHKEM_X25519_HKDF_SHA256;
    case HpkeParameters::KemId::kXWing:
      return HpkeKemProto::X_WING;
    case HpkeParameters::KemId::kMlKem768:
      return HpkeKemProto::ML_KEM768;
    case HpkeParameters::KemId::kMlKem1024:
      return HpkeKemProto::ML_KEM1024;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

absl::StatusOr<HpkeKdfProto> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdfProto::HKDF_SHA256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdfProto::HKDF_SHA384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdfProto::HKDF_SHA512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

absl::StatusOr<HpkeAeadProto> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAeadProto::AES_128_GCM;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAeadProto::AES_256_GCM;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return HpkeAeadProto::CHACHA20_POLY1305;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

absl::StatusOr<HpkeParamsProto> FromParameters(HpkeParameters parameters) {
  absl::StatusOr<HpkeKemProto> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  absl::StatusOr<HpkeKdfProto> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  absl::StatusOr<HpkeAeadProto> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  HpkeParamsProto params;
  params.set_kem(*kem);
  params.set_kdf(*kdf);
  params.set_aead(*aead);

  return params;
}

}  // namespace

absl::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const HpkePrivateKey& recipient_private_key) {
  absl::StatusOr<HpkeParamsProto> params =
      FromParameters(recipient_private_key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }
  return New(*params,
             recipient_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
                 .Get(InsecureSecretKeyAccess::Get()),
             recipient_private_key.GetOutputPrefix());
}

absl::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const HpkePrivateKeyProto& recipient_private_key) {
  if (recipient_private_key.private_key().empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is empty.");
  }
  if (!recipient_private_key.has_public_key()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing public key.");
  }
  if (!recipient_private_key.public_key().has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing HPKE parameters.");
  }
  return New(
      recipient_private_key.public_key().params(),
      util::SecretDataFromStringView(recipient_private_key.private_key()),
      /*output_prefix=*/"");
}

absl::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const google::crypto::tink::HpkeParams& hpke_params,
    const SecretData& recipient_private_key, absl::string_view output_prefix) {
  HpkeKemProto kem = hpke_params.kem();
  if (kem != HpkeKemProto::DHKEM_P256_HKDF_SHA256 &&
      kem != HpkeKemProto::DHKEM_X25519_HKDF_SHA256 &&
      kem != HpkeKemProto::X_WING && kem != HpkeKemProto::ML_KEM768 &&
      kem != HpkeKemProto::ML_KEM1024) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key has an unsupported KEM");
  }
  if (hpke_params.kdf() != HpkeKdfProto::HKDF_SHA256) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key has an unsupported KDF");
  }
  if (hpke_params.aead() == HpkeAeadProto::AEAD_UNKNOWN) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing AEAD");
  }
  return {absl::WrapUnique(
      new HpkeDecrypt(hpke_params, recipient_private_key, output_prefix))};
}

absl::StatusOr<std::string> HpkeDecrypt::DecryptNoPrefix(
    absl::string_view ciphertext, absl::string_view context_info) const {
  absl::StatusOr<int32_t> encoding_size_result =
      internal::HpkeEncapsulatedKeyLength(hpke_params_.kem());
  if (!encoding_size_result.ok()) return encoding_size_result.status();

  ABSL_CHECK_GE(*encoding_size_result, 0);
  size_t encoding_size = static_cast<size_t>(*encoding_size_result);
  // Verify that ciphertext length is at least the encapsulated key length.
  if (ciphertext.size() < encoding_size) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext is too short.");
  }
  absl::string_view encapsulated_key = ciphertext.substr(0, encoding_size);
  absl::string_view ciphertext_payload = ciphertext.substr(encoding_size);

  absl::StatusOr<internal::HpkeParams> params =
      internal::HpkeParamsProtoToStruct(hpke_params_);
  if (!params.ok()) return params.status();

  absl::StatusOr<std::unique_ptr<internal::HpkeContext>> recipient_context =
      internal::HpkeContext::SetupRecipient(*params, recipient_private_key_,
                                            encapsulated_key, context_info);
  if (!recipient_context.ok()) return recipient_context.status();

  return (*recipient_context)->Open(ciphertext_payload, /*associated_data=*/"");
}

absl::StatusOr<std::string> HpkeDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  if (!absl::StartsWith(ciphertext, output_prefix_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "OutputPrefix does not match");
  }
  return DecryptNoPrefix(absl::StripPrefix(ciphertext, output_prefix_),
                         context_info);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
