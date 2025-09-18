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

#include "tink/hybrid/internal/hpke_private_key_manager.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "tink/hybrid/internal/hpke_key_manager_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/xwing_util.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::EcPointFormat;
using ::crypto::tink::subtle::EllipticCurveType;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using HpkePrivateKeyProto = ::google::crypto::tink::HpkePrivateKey;
using HpkePublicKeyProto = ::google::crypto::tink::HpkePublicKey;

absl::Status GenerateX25519Key(HpkePublicKeyProto& public_key,
                               HpkePrivateKeyProto& private_key) {
  absl::StatusOr<std::unique_ptr<internal::X25519Key>> key =
      internal::NewX25519Key();
  if (!key.ok()) {
    return key.status();
  }
  public_key.set_public_key((*key)->public_value, X25519KeyPubKeySize());
  private_key.set_private_key(
      util::SecretDataAsStringView((*key)->private_key));
  return absl::OkStatus();
}

absl::Status GenerateEcKey(HpkePublicKeyProto& public_key,
                           HpkePrivateKeyProto& private_key,
                           EllipticCurveType ec_curve_type) {
  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(ec_curve_type);
  if (!ec_key.ok()) {
    return ec_key.status();
  }

  absl::StatusOr<SslUniquePtr<EC_POINT>> pub_point =
      internal::GetEcPoint(ec_curve_type, ec_key->pub_x, ec_key->pub_y);
  if (!pub_point.ok()) {
    return pub_point.status();
  }

  absl::StatusOr<std::string> encoded_pub_point = EcPointEncode(
      ec_curve_type, EcPointFormat::UNCOMPRESSED, pub_point->get());
  if (!encoded_pub_point.ok()) {
    return encoded_pub_point.status();
  }

  private_key.set_private_key(
      std::string(util::SecretDataAsStringView(ec_key->priv)));
  public_key.set_public_key(encoded_pub_point.value());
  return absl::OkStatus();
}

absl::Status GenerateXWingKey(HpkePublicKeyProto& public_key,
                              HpkePrivateKeyProto& private_key) {
  absl::StatusOr<XWingKey> key = NewXWingKey();
  if (!key.ok()) {
    return key.status();
  }
  public_key.set_public_key(key->public_key.data(), key->public_key.size());
  private_key.set_private_key(util::SecretDataAsStringView(key->private_key));
  return absl::OkStatus();
}

}  // namespace

absl::Status HpkePrivateKeyManager::ValidateKeyFormat(
    const HpkeKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return ValidateParams(key_format.params());
}

absl::StatusOr<HpkePrivateKeyProto> HpkePrivateKeyManager::CreateKey(
    const HpkeKeyFormat& key_format) const {
  // Set key metadata.
  HpkePrivateKeyProto private_key;
  private_key.set_version(get_version());
  HpkePublicKeyProto* public_key = private_key.mutable_public_key();
  public_key->set_version(get_version());
  *(public_key->mutable_params()) = key_format.params();
  // Generate key material.
  switch (key_format.params().kem()) {
    case HpkeKem::DHKEM_X25519_HKDF_SHA256: {
      absl::Status res = GenerateX25519Key(*public_key, private_key);
      if (!res.ok()) {
        return res;
      }
      break;
    }
    case HpkeKem::DHKEM_P256_HKDF_SHA256: {
      absl::Status res =
          GenerateEcKey(*public_key, private_key, EllipticCurveType::NIST_P256);
      if (!res.ok()) {
        return res;
      }
      break;
    }
    case HpkeKem::DHKEM_P384_HKDF_SHA384: {
      absl::Status res =
          GenerateEcKey(*public_key, private_key, EllipticCurveType::NIST_P384);
      if (!res.ok()) {
        return res;
      }
      break;
    }
    case HpkeKem::DHKEM_P521_HKDF_SHA512: {
      absl::Status res =
          GenerateEcKey(*public_key, private_key, EllipticCurveType::NIST_P521);
      if (!res.ok()) {
        return res;
      }
      break;
    }
    case HpkeKem::X_WING: {
      absl::Status res = GenerateXWingKey(*public_key, private_key);
      if (!res.ok()) {
        return res;
      }
      break;
    }
    default:
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unsupported KEM type: ", key_format.params().kem()));
  }
  return private_key;
}

absl::StatusOr<HpkePublicKeyProto> HpkePrivateKeyManager::GetPublicKey(
    const HpkePrivateKeyProto& private_key) const {
  return private_key.public_key();
}

absl::Status HpkePrivateKeyManager::ValidateKey(
    const HpkePrivateKeyProto& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_public_key()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Missing HPKE public key.");
  }
  return ValidateKeyAndVersion(key.public_key(), get_version());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
