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
#ifndef TINK_JWT_INTERNAL_JWT_HMAC_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_JWT_HMAC_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"
#include "proto/jwt_hmac.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

class JwtHmacKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtHmacKey,
                            google::crypto::tink::JwtHmacKeyFormat,
                            List<JwtMacInternal>> {
 public:
  class JwtMacFactory : public PrimitiveFactory<JwtMacInternal> {
    absl::StatusOr<std::unique_ptr<JwtMacInternal>> Create(
        const google::crypto::tink::JwtHmacKey& jwt_hmac_key) const override;
  };

  JwtHmacKeyManager() : KeyTypeManager(absl::make_unique<JwtMacFactory>()) {}

  uint32_t get_version() const override;

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override;

  const std::string& get_key_type() const override;

  absl::Status ValidateKey(
      const google::crypto::tink::JwtHmacKey& key) const override;

  absl::Status ValidateKeyFormat(
      const google::crypto::tink::JwtHmacKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::JwtHmacKey> CreateKey(
      const google::crypto::tink::JwtHmacKeyFormat& key_format) const override;

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  const RawJwtHmacKeyManager raw_key_manager_;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_HMAC_KEY_MANAGER_H_
