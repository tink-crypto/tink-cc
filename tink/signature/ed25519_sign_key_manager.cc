// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_sign_key_manager.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/safe_stringops.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ed25519.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::internal::SecretBuffer;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::Ed25519KeyFormat;
using Ed25519PrivateKeyProto = ::google::crypto::tink::Ed25519PrivateKey;

absl::StatusOr<Ed25519PrivateKeyProto> Ed25519SignKeyManager::CreateKey(
    const Ed25519KeyFormat& key_format) const {
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
      internal::NewEd25519Key();
  if (!key.ok()) {
    return key.status();
  }

  Ed25519PrivateKeyProto ed25519_private_key;
  ed25519_private_key.set_version(get_version());
  ed25519_private_key.set_key_value(
      util::SecretDataAsStringView((*key)->private_key));

  // Build Ed25519PublicKey.
  auto ed25519_public_key = ed25519_private_key.mutable_public_key();
  ed25519_public_key->set_version(get_version());
  ed25519_public_key->set_key_value((*key)->public_key);

  return ed25519_private_key;
}

absl::StatusOr<std::unique_ptr<PublicKeySign>>
Ed25519SignKeyManager::PublicKeySignFactory::Create(
    const Ed25519PrivateKeyProto& private_key) const {
  // BoringSSL expects a 64-byte private key which contains the public key as a
  // suffix.
  SecretBuffer sk(private_key.key_value().size() +
                  private_key.public_key().key_value().size());
  internal::SafeMemCopy(
      sk.data(),
      reinterpret_cast<const uint8_t*>(private_key.key_value().data()),
      private_key.key_value().size());
  internal::SafeMemCopy(sk.data() + private_key.key_value().size(),
                        reinterpret_cast<const uint8_t*>(
                            private_key.public_key().key_value().data()),
                        private_key.public_key().key_value().size());

  return subtle::Ed25519SignBoringSsl::New(
      util::internal::AsSecretData(std::move(sk)));
}

Status Ed25519SignKeyManager::ValidateKey(
    const Ed25519PrivateKeyProto& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().length() != 32) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "The ED25519 private key must be 32-bytes long.");
  }
  return Ed25519VerifyKeyManager().ValidateKey(key.public_key());
}

absl::StatusOr<Ed25519PrivateKeyProto> Ed25519SignKeyManager::DeriveKey(
    const Ed25519KeyFormat& key_format, InputStream* input_stream) const {
  absl::Status status = ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;

  absl::StatusOr<util::SecretData> randomness =
      ReadSecretBytesFromStream(kEd25519SecretSeedSize, input_stream);
  if (!randomness.ok()) {
    if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Could not get enough pseudorandomness from input stream");
    }
    return randomness.status();
  }
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
      internal::NewEd25519Key(*randomness);

  Ed25519PrivateKeyProto ed25519_private_key;
  ed25519_private_key.set_version(get_version());
  ed25519_private_key.set_key_value(
      util::SecretDataAsStringView((*key)->private_key));

  // Build Ed25519PublicKey.
  auto ed25519_public_key = ed25519_private_key.mutable_public_key();
  ed25519_public_key->set_version(get_version());
  ed25519_public_key->set_key_value((*key)->public_key);

  return ed25519_private_key;
}

Status Ed25519SignKeyManager::ValidateKeyFormat(
    const Ed25519KeyFormat& key_format) const {
  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
