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
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/jwt/internal/jwt_public_key_sign_impl.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/public_key_sign.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using google::crypto::tink::JwtRsaSsaPkcs1PrivateKey;
using google::crypto::tink::JwtRsaSsaPkcs1PublicKey;

absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>>
JwtRsaSsaPkcs1SignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPkcs1PrivateKey& jwt_rsa_ssa_pkcs1_private_key) const {
  absl::StatusOr<std::string> name =
      JwtRsaSsaPkcs1VerifyKeyManager::AlgorithmName(
          jwt_rsa_ssa_pkcs1_private_key.public_key().algorithm());
  if (!name.ok()) {
    return name.status();
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> sign =
      raw_key_manager_.GetPrimitive<PublicKeySign>(
          jwt_rsa_ssa_pkcs1_private_key);
  if (!sign.ok()) {
    return sign.status();
  }
  absl::optional<absl::string_view> custom_kid = absl::nullopt;
  if (jwt_rsa_ssa_pkcs1_private_key.public_key().has_custom_kid()) {
    custom_kid =
        jwt_rsa_ssa_pkcs1_private_key.public_key().custom_kid().value();
  }
  if (custom_kid.has_value()) {
    return jwt_internal::JwtPublicKeySignImpl::RawWithCustomKid(
        *std::move(sign), *name, *custom_kid);
  }
  return jwt_internal::JwtPublicKeySignImpl::Raw(*std::move(sign), *name);
}

uint32_t JwtRsaSsaPkcs1SignKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtRsaSsaPkcs1SignKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtRsaSsaPkcs1SignKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
JwtRsaSsaPkcs1SignKeyManager::CreateKey(
    const JwtRsaSsaPkcs1KeyFormat& key_format) const {
  return raw_key_manager_.CreateKey(key_format);
}

absl::Status JwtRsaSsaPkcs1SignKeyManager::ValidateKey(
    const JwtRsaSsaPkcs1PrivateKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

absl::Status JwtRsaSsaPkcs1SignKeyManager::ValidateKeyFormat(
    const JwtRsaSsaPkcs1KeyFormat& key_format) const {
  return raw_key_manager_.ValidateKeyFormat(key_format);
}

absl::StatusOr<JwtRsaSsaPkcs1PublicKey>
JwtRsaSsaPkcs1SignKeyManager::GetPublicKey(
    const JwtRsaSsaPkcs1PrivateKey& private_key) const {
  return raw_key_manager_.GetPublicKey(private_key);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
