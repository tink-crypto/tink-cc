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

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
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
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::HpkePrivateKey;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeParams;
using HpkePrivateKeyProto = ::google::crypto::tink::HpkePrivateKey;

util::StatusOr<HpkeKem> FromKemId(HpkeParameters::KemId kem_id) {
  switch (kem_id) {
    case HpkeParameters::KemId::kDhkemP256HkdfSha256:
      return HpkeKem::DHKEM_P256_HKDF_SHA256;
    case HpkeParameters::KemId::kDhkemP384HkdfSha384:
      return HpkeKem::DHKEM_P384_HKDF_SHA384;
    case HpkeParameters::KemId::kDhkemP521HkdfSha512:
      return HpkeKem::DHKEM_P521_HKDF_SHA512;
    case HpkeParameters::KemId::kDhkemX25519HkdfSha256:
      return HpkeKem::DHKEM_X25519_HKDF_SHA256;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KEM.");
  }
}

util::StatusOr<HpkeKdf> FromKdfId(HpkeParameters::KdfId kdf_id) {
  switch (kdf_id) {
    case HpkeParameters::KdfId::kHkdfSha256:
      return HpkeKdf::HKDF_SHA256;
    case HpkeParameters::KdfId::kHkdfSha384:
      return HpkeKdf::HKDF_SHA384;
    case HpkeParameters::KdfId::kHkdfSha512:
      return HpkeKdf::HKDF_SHA512;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine KDF.");
  }
}

util::StatusOr<HpkeAead> FromAeadId(HpkeParameters::AeadId aead_id) {
  switch (aead_id) {
    case HpkeParameters::AeadId::kAesGcm128:
      return HpkeAead::AES_128_GCM;
    case HpkeParameters::AeadId::kAesGcm256:
      return HpkeAead::AES_256_GCM;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      return HpkeAead::CHACHA20_POLY1305;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Could not determine AEAD.");
  }
}

util::StatusOr<HpkeParams> FromParameters(HpkeParameters parameters) {
  util::StatusOr<HpkeKem> kem = FromKemId(parameters.GetKemId());
  if (!kem.ok()) {
    return kem.status();
  }

  util::StatusOr<HpkeKdf> kdf = FromKdfId(parameters.GetKdfId());
  if (!kdf.ok()) {
    return kdf.status();
  }

  util::StatusOr<HpkeAead> aead = FromAeadId(parameters.GetAeadId());
  if (!aead.ok()) {
    return aead.status();
  }

  HpkeParams params;
  params.set_kem(*kem);
  params.set_kdf(*kdf);
  params.set_aead(*aead);

  return params;
}

}  // namespace

util::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const HpkePrivateKey& recipient_private_key) {
  util::StatusOr<HpkeParams> params =
      FromParameters(recipient_private_key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }
  return New(*params,
             recipient_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
                 .Get(InsecureSecretKeyAccess::Get()),
             recipient_private_key.GetOutputPrefix());
}

util::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const HpkePrivateKeyProto& recipient_private_key) {
  if (recipient_private_key.private_key().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is empty.");
  }
  if (!recipient_private_key.has_public_key()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing public key.");
  }
  if (!recipient_private_key.public_key().has_params()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing HPKE parameters.");
  }
  return New(
      recipient_private_key.public_key().params(),
      util::SecretDataFromStringView(recipient_private_key.private_key()),
      /*output_prefix=*/"");
}

util::StatusOr<std::unique_ptr<HybridDecrypt>> HpkeDecrypt::New(
    const google::crypto::tink::HpkeParams& hpke_params,
    const util::SecretData& recipient_private_key,
    absl::string_view output_prefix) {
  HpkeKem kem = hpke_params.kem();
  if (kem != HpkeKem::DHKEM_P256_HKDF_SHA256 &&
      kem != HpkeKem::DHKEM_X25519_HKDF_SHA256) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key has an unsupported KEM");
  }
  if (hpke_params.kdf() != HpkeKdf::HKDF_SHA256) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key has an unsupported KDF");
  }
  if (hpke_params.aead() == HpkeAead::AEAD_UNKNOWN) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is missing AEAD");
  }
  return {absl::WrapUnique(
      new HpkeDecrypt(hpke_params, recipient_private_key, output_prefix))};
}

util::StatusOr<std::string> HpkeDecrypt::DecryptNoPrefix(
    absl::string_view ciphertext, absl::string_view context_info) const {
  util::StatusOr<int32_t> encoding_size =
      internal::HpkeEncapsulatedKeyLength(hpke_params_.kem());
  if (!encoding_size.ok()) return encoding_size.status();

  // Verify that ciphertext length is at least the encapsulated key length.
  if (ciphertext.size() < *encoding_size) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext is too short.");
  }
  absl::string_view encapsulated_key = ciphertext.substr(0, *encoding_size);
  absl::string_view ciphertext_payload = ciphertext.substr(*encoding_size);

  util::StatusOr<internal::HpkeParams> params =
      internal::HpkeParamsProtoToStruct(hpke_params_);
  if (!params.ok()) return params.status();

  util::StatusOr<std::unique_ptr<internal::HpkeContext>> recipient_context =
      internal::HpkeContext::SetupRecipient(*params, recipient_private_key_,
                                            encapsulated_key, context_info);
  if (!recipient_context.ok()) return recipient_context.status();

  return (*recipient_context)->Open(ciphertext_payload, /*associated_data=*/"");
}

util::StatusOr<std::string> HpkeDecrypt::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  if (!absl::StartsWith(ciphertext, output_prefix_)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "OutputPrefix does not match");
  }
  return DecryptNoPrefix(absl::StripPrefix(ciphertext, output_prefix_),
                         context_info);
}

}  // namespace tink
}  // namespace crypto
