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

#ifndef TINK_JWT_INTERNAL_RAW_JWT_RSA_SSA_PKCS1_VERIFY_KEY_MANAGER_H_
#define TINK_JWT_INTERNAL_RAW_JWT_RSA_SSA_PKCS1_VERIFY_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/util/constants.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class RawJwtRsaSsaPkcs1VerifyKeyManager
    : public KeyTypeManager<google::crypto::tink::JwtRsaSsaPkcs1PublicKey, void,
                            List<PublicKeyVerify>> {
 public:
  class PublicKeyVerifyFactory : public PrimitiveFactory<PublicKeyVerify> {
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Create(
        const google::crypto::tink::JwtRsaSsaPkcs1PublicKey&
            jwt_rsa_ssa_pkcs1_public_key) const override;
  };

  RawJwtRsaSsaPkcs1VerifyKeyManager()
      : KeyTypeManager(absl::make_unique<PublicKeyVerifyFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::JwtRsaSsaPkcs1PublicKey& key) const override;

  internal::FipsCompatibility FipsStatus() const override {
    return internal::FipsCompatibility::kRequiresBoringCrypto;
  }

 private:
  static absl::Status ValidateAlgorithm(
      const google::crypto::tink::JwtRsaSsaPkcs1Algorithm& algorithm);

  static absl::StatusOr<google::crypto::tink::HashType> HashForPkcs1Algorithm(
      const google::crypto::tink::JwtRsaSsaPkcs1Algorithm& algorithm);

  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom,
      google::crypto::tink::JwtRsaSsaPkcs1PublicKey().GetTypeName());
  friend class RawJwtRsaSsaPkcs1SignKeyManager;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_RAW_JWT_RSA_SSA_PKCS1_VERIFY_KEY_MANAGER_H_
