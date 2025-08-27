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
#include "tink/big_integer.h"
#include "tink/daead/aes_siv_key.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/aes_siv_proto_serialization.h"
#include "tink/ec_point.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/hmac_proto_serialization.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/aes_cmac_prf_proto_serialization.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hkdf_prf_proto_serialization.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/secret_data.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

constexpr int kEd25519PrivKeyLen = 32;
constexpr int kXChaCha20Poly1305KeyLen = 32;

using KeyDeriverFn = absl::AnyInvocable<absl::StatusOr<std::unique_ptr<Key>>(
    const Parameters&, InputStream*) const>;
using KeyDeriverFnMap = absl::flat_hash_map<std::type_index, KeyDeriverFn>;

absl::StatusOr<std::unique_ptr<AesCtrHmacAeadKey>> DeriveAesCtrHmacAeadKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  // To ensure the resulting key provides key commitment, derive the AES key
  // first, then the HMAC key.
  //
  // Consider the following scenario:
  //   - Derive the HMAC key before the AES key from the keystream.
  //   - Brute force raw key material so the 32nd byte of the keystream is 0.
  //   - Give party A a key with this raw key material with HMAC key size 32
  //     bytes and AES key size 16 bytes.
  //   - Give party B a key with this raw key material with HMAC key size 31
  //     bytes and AES key size 16 bytes.
  //   - HMAC pads its key with zeroes, so both parties will end up with the
  //     same HMAC key, but different AES keys (offset by 1 byte).

  const AesCtrHmacAeadParameters* params =
      dynamic_cast<const AesCtrHmacAeadParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesCtrHmacAeadParameters.");
  }
  absl::StatusOr<std::string> aes_key_bytes =
      ReadBytesFromStream(params->GetAesKeySizeInBytes(), rand_stream);
  if (!aes_key_bytes.ok()) {
    return aes_key_bytes.status();
  }
  absl::StatusOr<std::string> hmac_key_bytes =
      ReadBytesFromStream(params->GetHmacKeySizeInBytes(), rand_stream);
  if (!hmac_key_bytes.ok()) {
    return hmac_key_bytes.status();
  }
  absl::StatusOr<AesCtrHmacAeadKey> key =
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

absl::StatusOr<std::unique_ptr<AesGcmKey>> DeriveAesGcmKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const AesGcmParameters* params =
      dynamic_cast<const AesGcmParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesGcmParameters.");
  }
  absl::StatusOr<std::string> rand =
      ReadBytesFromStream(params->KeySizeInBytes(), rand_stream);
  if (!rand.ok()) {
    return rand.status();
  }
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, RestrictedData(*rand, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesGcmKey>(*key);
}

absl::StatusOr<std::unique_ptr<XChaCha20Poly1305Key>>
DeriveXChaCha20Poly1305Key(const Parameters& generic_params,
                           InputStream* rand_stream) {
  const XChaCha20Poly1305Parameters* params =
      dynamic_cast<const XChaCha20Poly1305Parameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not XChaCha20Poly1305Parameters.");
  }
  absl::StatusOr<std::string> rand =
      ReadBytesFromStream(kXChaCha20Poly1305KeyLen, rand_stream);
  if (!rand.ok()) {
    return rand.status();
  }
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params->GetVariant(),
      RestrictedData(*rand, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<XChaCha20Poly1305Key>(*key);
}

absl::StatusOr<std::unique_ptr<AesSivKey>> DeriveAesSivKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const AesSivParameters* params =
      dynamic_cast<const AesSivParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesSivParameters.");
  }
  absl::StatusOr<SecretData> rand =
      ReadSecretBytesFromStream(params->KeySizeInBytes(), rand_stream);
  if (!rand.ok()) {
    return rand.status();
  }
  absl::StatusOr<AesSivKey> key = AesSivKey::Create(
      *params, RestrictedData(*rand, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesSivKey>(*key);
}

absl::StatusOr<std::unique_ptr<HmacKey>> DeriveHmacKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const HmacParameters* params =
      dynamic_cast<const HmacParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not HmacParameters.");
  }
  absl::StatusOr<std::string> rand =
      ReadBytesFromStream(params->KeySizeInBytes(), rand_stream);
  if (!rand.ok()) {
    return rand.status();
  }
  absl::StatusOr<HmacKey> key = HmacKey::Create(
      *params, RestrictedData(*rand, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<HmacKey>(*key);
}

absl::StatusOr<std::unique_ptr<AesCmacPrfKey>> DeriveAesCmacPrfKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const AesCmacPrfParameters* params =
      dynamic_cast<const AesCmacPrfParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesCmacPrfParameters.");
  }
  absl::StatusOr<std::string> rand =
      ReadBytesFromStream(params->KeySizeInBytes(), rand_stream);
  if (!rand.ok()) {
    return rand.status();
  }
  absl::StatusOr<AesCmacPrfKey> key = AesCmacPrfKey::Create(
      RestrictedData(*rand, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesCmacPrfKey>(*key);
}

absl::StatusOr<std::unique_ptr<HkdfPrfKey>> DeriveHkdfPrfKey(
    const Parameters& generic_params, InputStream* randomness) {
  const HkdfPrfParameters* params =
      dynamic_cast<const HkdfPrfParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not HkdfPrfParameters.");
  }
  absl::StatusOr<std::string> randomness_str =
      ReadBytesFromStream(params->KeySizeInBytes(), randomness);
  if (!randomness_str.ok()) {
    return randomness_str.status();
  }
  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      *params, RestrictedData(*randomness_str, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<HkdfPrfKey>(*key);
}

absl::StatusOr<std::unique_ptr<EcdsaPrivateKey>> DeriveEcdsaPrivateKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const EcdsaParameters* params =
      dynamic_cast<const EcdsaParameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not EcdsaParameters.");
  }

  subtle::EllipticCurveType curve_type;
  int num_rand_bytes = 0;
  switch (params->GetCurveType()) {
    case EcdsaParameters::CurveType::kNistP256:
      curve_type = subtle::EllipticCurveType::NIST_P256;
      num_rand_bytes = 16;
      break;
    case EcdsaParameters::CurveType::kNistP384:
      curve_type = subtle::EllipticCurveType::NIST_P384;
      num_rand_bytes = 24;
      break;
    case EcdsaParameters::CurveType::kNistP521:
      curve_type = subtle::EllipticCurveType::NIST_P521;
      num_rand_bytes = 32;
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "ECDSA curve does not support key derivation.");
  }
  absl::StatusOr<SecretData> secret_seed =
      ReadSecretBytesFromStream(num_rand_bytes, rand_stream);
  if (!secret_seed.ok()) {
    return secret_seed.status();
  }
  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(curve_type, *secret_seed);
  if (!ec_key.ok()) {
    return ec_key.status();
  }

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, public_point, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }
  return absl::make_unique<EcdsaPrivateKey>(*private_key);
}

absl::StatusOr<std::unique_ptr<Ed25519PrivateKey>> DeriveEd25519PrivateKey(
    const Parameters& generic_params, InputStream* rand_stream) {
  const Ed25519Parameters* params =
      dynamic_cast<const Ed25519Parameters*>(&generic_params);
  if (params == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Parameters is not Ed25519Parameters.");
  }

  absl::StatusOr<SecretData> secret_seed =
      ReadSecretBytesFromStream(kEd25519PrivKeyLen, rand_stream);
  if (!secret_seed.ok()) {
    return secret_seed.status();
  }
  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key(*secret_seed);
  if (!key_pair.ok()) {
    return key_pair.status();
  }

  absl::StatusOr<Ed25519PublicKey> public_key = Ed25519PublicKey::Create(
      *params, (*key_pair)->public_key,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());
  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }
  return absl::make_unique<Ed25519PrivateKey>(*private_key);
}

const KeyDeriverFnMap& ParametersToKeyDeriver() {
  static const KeyDeriverFnMap* instance = [] {
    static KeyDeriverFnMap* m = new KeyDeriverFnMap();

    // AEAD.
    CHECK_OK(RegisterAesCtrHmacAeadProtoSerialization());
    m->insert({std::type_index(typeid(AesCtrHmacAeadParameters)),
               DeriveAesCtrHmacAeadKey});
    CHECK_OK(RegisterAesGcmProtoSerialization());
    m->insert({std::type_index(typeid(AesGcmParameters)), DeriveAesGcmKey});
    CHECK_OK(RegisterXChaCha20Poly1305ProtoSerialization());
    m->insert({std::type_index(typeid(XChaCha20Poly1305Parameters)),
               DeriveXChaCha20Poly1305Key});

    // Deterministic AEAD.
    CHECK_OK(RegisterAesSivProtoSerialization());
    m->insert({std::type_index(typeid(AesSivParameters)), DeriveAesSivKey});

    // MAC.
    CHECK_OK(RegisterHmacProtoSerialization());
    m->insert({std::type_index(typeid(HmacParameters)), DeriveHmacKey});

    // PRF.
    CHECK_OK(RegisterAesCmacPrfProtoSerialization());
    m->insert(
        {std::type_index(typeid(AesCmacPrfParameters)), DeriveAesCmacPrfKey});
    CHECK_OK(RegisterHkdfPrfProtoSerialization());
    m->insert({std::type_index(typeid(HkdfPrfParameters)), DeriveHkdfPrfKey});

    // Signature.
    CHECK_OK(RegisterEcdsaProtoSerialization());
    m->insert(
        {std::type_index(typeid(EcdsaParameters)), DeriveEcdsaPrivateKey});
    CHECK_OK(RegisterEd25519ProtoSerialization());
    m->insert(
        {std::type_index(typeid(Ed25519Parameters)), DeriveEd25519PrivateKey});

    return m;
  }();
  return *instance;
}

}  // namespace

absl::StatusOr<std::unique_ptr<Key>> DeriveKey(const Parameters& params,
                                               InputStream* rand_stream) {
  auto it = ParametersToKeyDeriver().find(std::type_index(typeid(params)));
  if (it == ParametersToKeyDeriver().end()) {
    return absl::Status(
        absl::StatusCode::kUnimplemented,
        absl::StrCat("Key deriver not found for ", typeid(params).name()));
  }
  return it->second(params, rand_stream);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
