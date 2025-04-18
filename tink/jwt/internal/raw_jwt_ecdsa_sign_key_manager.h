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
#ifndef TINK_JWT_INTERNAL_RAW_JWT_ECDSA_SIGN_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_RAW_JWT_ECDSA_SIGN_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/util/constants.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class RawJwtEcdsaSignKeyManager
    : public PrivateKeyTypeManager<google::crypto::tink::JwtEcdsaPrivateKey,
                                   google::crypto::tink::JwtEcdsaKeyFormat,
                                   google::crypto::tink::JwtEcdsaPublicKey,
                                   List<PublicKeySign>> {
 public:
  class PublicKeySignFactory : public PrimitiveFactory<PublicKeySign> {
    absl::StatusOr<std::unique_ptr<PublicKeySign>> Create(
        const google::crypto::tink::JwtEcdsaPrivateKey& private_key)
        const override;
  };

  RawJwtEcdsaSignKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<PublicKeySignFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::JwtEcdsaPrivateKey& key) const override;

  absl::Status ValidateKeyFormat(
      const google::crypto::tink::JwtEcdsaKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::JwtEcdsaPrivateKey> CreateKey(
      const google::crypto::tink::JwtEcdsaKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::JwtEcdsaPublicKey> GetPublicKey(
      const google::crypto::tink::JwtEcdsaPrivateKey& private_key)
      const override {
    return private_key.public_key();
  }

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom,
                   google::crypto::tink::JwtEcdsaPrivateKey().GetTypeName());
};

}  // namespace jwt_internal

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_RAW_JWT_ECDSA_SIGN_KEY_MANAGER_H_
