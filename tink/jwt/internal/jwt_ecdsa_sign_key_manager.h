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
#ifndef TINK_JWT_INTERNAL_JWT_ECDSA_SIGN_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_ECDSA_SIGN_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/internal/raw_jwt_ecdsa_sign_key_manager.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtEcdsaSignKeyManager
    : public PrivateKeyTypeManager<google::crypto::tink::JwtEcdsaPrivateKey,
                                   google::crypto::tink::JwtEcdsaKeyFormat,
                                   google::crypto::tink::JwtEcdsaPublicKey,
                                   List<JwtPublicKeySignInternal>> {
 public:
  class PublicKeySignFactory
      : public PrimitiveFactory<JwtPublicKeySignInternal> {
    absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> Create(
        const google::crypto::tink::JwtEcdsaPrivateKey& private_key)
        const override;

   private:
    const RawJwtEcdsaSignKeyManager raw_key_manager_;
  };

  JwtEcdsaSignKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<PublicKeySignFactory>()) {}

  uint32_t get_version() const override;

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override;

  const std::string& get_key_type() const override;

  absl::Status ValidateKey(
      const google::crypto::tink::JwtEcdsaPrivateKey& key) const override;

  absl::Status ValidateKeyFormat(
      const google::crypto::tink::JwtEcdsaKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::JwtEcdsaPrivateKey> CreateKey(
      const google::crypto::tink::JwtEcdsaKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::JwtEcdsaPublicKey> GetPublicKey(
      const google::crypto::tink::JwtEcdsaPrivateKey& private_key)
      const override;

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  const RawJwtEcdsaSignKeyManager raw_key_manager_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ECDSA_SIGN_KEY_MANAGER_H_
