// Copyright 2017 Google Inc.
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
#ifndef TINK_HYBRID_ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_H_
#define TINK_HYBRID_ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class EciesAeadHkdfPublicKeyManager
    : public KeyTypeManager<google::crypto::tink::EciesAeadHkdfPublicKey, void,
                            List<HybridEncrypt>> {
 public:
  class HybridEncryptFactory : public PrimitiveFactory<HybridEncrypt> {
    absl::StatusOr<std::unique_ptr<HybridEncrypt>> Create(
        const google::crypto::tink::EciesAeadHkdfPublicKey& ecies_public_key)
        const override {
      return EciesAeadHkdfHybridEncrypt::New(ecies_public_key);
    }
  };

  EciesAeadHkdfPublicKeyManager()
      : KeyTypeManager(absl::make_unique<HybridEncryptFactory>()) {}

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::EciesAeadHkdfPublicKey& key) const override;

  absl::Status ValidateParams(
      const google::crypto::tink::EciesAeadHkdfParams& params) const;

 private:
  const std::string key_type_ = absl::StrCat(
      kTypeGoogleapisCom,
      google::crypto::tink::EciesAeadHkdfPublicKey().GetTypeName());
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_ECIES_AEAD_HKDF_PUBLIC_KEY_MANAGER_H_
