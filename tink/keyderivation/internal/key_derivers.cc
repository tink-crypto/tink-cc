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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/key_derivers.h"

#include <memory>
#include <string>
#include <typeindex>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

constexpr int kXChaCha20Poly1305KeyLen = 32;

using KeyDeriverFn = absl::AnyInvocable<util::StatusOr<std::unique_ptr<Key>>(
    const Parameters&, InputStream*) const>;
using KeyDeriverFnMap = absl::flat_hash_map<std::type_index, KeyDeriverFn>;

// AEAD.

util::StatusOr<std::unique_ptr<AesGcmKey>> DeriveAesGcmKey(
    const Parameters& generic_params, InputStream* randomness) {
  const AesGcmParameters* params =
      dynamic_cast<const AesGcmParameters*>(&generic_params);
  if (params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesGcmParameters.");
  }
  util::StatusOr<std::string> randomness_str =
      ReadBytesFromStream(params->KeySizeInBytes(), randomness);
  if (!randomness_str.ok()) {
    return randomness_str.status();
  }
  util::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, RestrictedData(*randomness_str, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesGcmKey>(*key);
}

util::StatusOr<std::unique_ptr<XChaCha20Poly1305Key>>
DeriveXChaCha20Poly1305Key(const Parameters& generic_params,
                           InputStream* randomness) {
  const XChaCha20Poly1305Parameters* params =
      dynamic_cast<const XChaCha20Poly1305Parameters*>(&generic_params);
  if (params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Parameters is not XChaCha20Poly1305Parameters.");
  }
  util::StatusOr<std::string> randomness_str =
      ReadBytesFromStream(kXChaCha20Poly1305KeyLen, randomness);
  if (!randomness_str.ok()) {
    return randomness_str.status();
  }
  util::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params->GetVariant(),
      RestrictedData(*randomness_str, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<XChaCha20Poly1305Key>(*key);
}

// To ensure the resulting key provides key commitment, derive the AES key
// first, then the HMAC key.
//
// Consider the following scenario:
//   - Derive the HMAC key before the AES key from the keystream.
//   - Brute force the raw key material so the 32nd byte of the keystream is 0.
//   - Give party A a key with this raw key material with HMAC key size 32 bytes
//     and AES key size 16 bytes.
//   - Give party B a key with this raw key material with HMAC key size 31 bytes
//     and AES key size 16 bytes.
//   - HMAC pads its key with zeroes, so both parties will end up with the same
//     HMAC key, but different AES keys (offset by 1 byte).
util::StatusOr<std::unique_ptr<AesCtrHmacAeadKey>> DeriveAesCtrHmacAeadKey(
    const Parameters& generic_params, InputStream* randomness) {
  const AesCtrHmacAeadParameters* params =
      dynamic_cast<const AesCtrHmacAeadParameters*>(&generic_params);
  if (params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesCtrHmacAeadParameters.");
  }
  util::StatusOr<std::string> aes_key_bytes =
      ReadBytesFromStream(params->GetAesKeySizeInBytes(), randomness);
  if (!aes_key_bytes.ok()) {
    return aes_key_bytes.status();
  }
  util::StatusOr<std::string> hmac_key_bytes =
      ReadBytesFromStream(params->GetHmacKeySizeInBytes(), randomness);
  if (!hmac_key_bytes.ok()) {
    return hmac_key_bytes.status();
  }
  util::StatusOr<AesCtrHmacAeadKey> key =
      AesCtrHmacAeadKey::Builder()
          .SetParameters(*params)
          .SetAesKeyBytes(
              RestrictedData(*aes_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetHmacKeyBytes(
              RestrictedData(*hmac_key_bytes, InsecureSecretKeyAccess::Get()))
          .SetIdRequirement(absl::nullopt)
          .Build(GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesCtrHmacAeadKey>(*key);
}

const KeyDeriverFnMap& ParametersToKeyDeriver() {
  static const KeyDeriverFnMap* instance = [] {
    static KeyDeriverFnMap* m = new KeyDeriverFnMap();

    // AEAD.
    CHECK_OK(RegisterAesGcmProtoSerialization());
    m->insert({std::type_index(typeid(AesGcmParameters)), DeriveAesGcmKey});
    CHECK_OK(RegisterXChaCha20Poly1305ProtoSerialization());
    m->insert({std::type_index(typeid(XChaCha20Poly1305Parameters)),
               DeriveXChaCha20Poly1305Key});
    CHECK_OK(RegisterAesCtrHmacAeadProtoSerialization());
    m->insert({std::type_index(typeid(AesCtrHmacAeadParameters)),
               DeriveAesCtrHmacAeadKey});

    return m;
  }();
  return *instance;
}

}  // namespace

util::StatusOr<std::unique_ptr<Key>> DeriveKey(const Parameters& params,
                                               InputStream* randomness) {
  auto it = ParametersToKeyDeriver().find(std::type_index(typeid(params)));
  if (it == ParametersToKeyDeriver().end()) {
    return util::Status(
        absl::StatusCode::kUnimplemented,
        absl::StrCat("Key deriver not found for ", typeid(params).name()));
  }
  return it->second(params, randomness);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
