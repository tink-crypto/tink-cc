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

#include "tink/hybrid/internal/hpke_encrypt.h"

#include <memory>
#include <new>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/hpke_context.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid_encrypt.h"
#include "tink/partial_key_access.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using HpkeAeadProto = ::google::crypto::tink::HpkeAead;
using HpkeKdfProto = ::google::crypto::tink::HpkeKdf;
using HpkeKemProto = ::google::crypto::tink::HpkeKem;
using HpkePublicKeyProto = ::google::crypto::tink::HpkePublicKey;
using HpkeParamsProto = ::google::crypto::tink::HpkeParams;

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

absl::StatusOr<std::unique_ptr<HybridEncrypt>> HpkeEncrypt::New(
    const HpkePublicKey& recipient_public_key) {
  absl::StatusOr<HpkeParamsProto> params =
      FromParameters(recipient_public_key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }
  HpkePublicKeyProto proto;
  proto.set_public_key(
      recipient_public_key.GetPublicKeyBytes(GetPartialKeyAccess()));
  *proto.mutable_params() = *params;
  proto.set_version(0);
  return New(proto, recipient_public_key.GetOutputPrefix());
}

absl::StatusOr<std::unique_ptr<HybridEncrypt>> HpkeEncrypt::New(
    const HpkePublicKeyProto& recipient_public_key) {
  return New(recipient_public_key, /*output_prefix=*/"");
}

absl::StatusOr<std::unique_ptr<HybridEncrypt>> HpkeEncrypt::New(
    const HpkePublicKeyProto& recipient_public_key,
    absl::string_view output_prefix) {
  if (recipient_public_key.public_key().empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is empty.");
  }
  if (!recipient_public_key.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is missing HPKE parameters.");
  }
  HpkeKemProto kem = recipient_public_key.params().kem();
  if (kem != HpkeKemProto::DHKEM_P256_HKDF_SHA256 &&
      kem != HpkeKemProto::DHKEM_X25519_HKDF_SHA256) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key has an unsupported KEM");
  }
  if (recipient_public_key.params().kdf() != HpkeKdfProto::HKDF_SHA256) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key has an unsupported KDF");
  }
  if (recipient_public_key.params().aead() == HpkeAeadProto::AEAD_UNKNOWN) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is missing AEAD");
  }
  return {
      absl::WrapUnique(new HpkeEncrypt(recipient_public_key, output_prefix))};
}

absl::StatusOr<std::string> HpkeEncrypt::EncryptNoPrefix(
    absl::string_view plaintext, absl::string_view context_info) const {
  absl::StatusOr<internal::HpkeParams> params =
      internal::HpkeParamsProtoToStruct(recipient_public_key_.params());
  if (!params.ok()) return params.status();

  absl::StatusOr<std::unique_ptr<internal::HpkeContext>> sender_context =
      internal::HpkeContext::SetupSender(
          *params, recipient_public_key_.public_key(), context_info);
  if (!sender_context.ok()) return sender_context.status();

  absl::StatusOr<std::string> ciphertext =
      (*sender_context)->Seal(plaintext, /*associated_data=*/"");
  if (!ciphertext.ok()) return ciphertext.status();

  return internal::ConcatenatePayload((*sender_context)->EncapsulatedKey(),
                                      *ciphertext);
}

absl::StatusOr<std::string> HpkeEncrypt::Encrypt(
    absl::string_view plaintext, absl::string_view context_info) const {
  absl::StatusOr<std::string> ciphertext_no_prefix =
      EncryptNoPrefix(plaintext, context_info);
  if (!ciphertext_no_prefix.ok()) {
    return ciphertext_no_prefix.status();
  }
  return absl::StrCat(output_prefix_, *ciphertext_no_prefix);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
