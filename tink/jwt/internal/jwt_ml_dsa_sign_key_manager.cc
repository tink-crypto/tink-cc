// Copyright 2026 Google LLC
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

#include "tink/jwt/internal/jwt_ml_dsa_sign_key_manager.h"

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/legacy_key_manager_impl.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/internal/jwt_ml_dsa_key_creator.h"
#include "tink/jwt/internal/jwt_ml_dsa_signer.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/parameters.h"
#include "tink/util/constants.h"
#include "tink/util/protobuf_helper.h"
#include "proto/jwt_ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class JwtMlDsaSignKeyManagerAdaptor
    : public LegacyKeyManagerAdaptor<JwtPublicKeySignInternal> {
 public:
  class PublicKeySignFactoryAdaptor : public LegacyPrivateKeyFactoryAdaptor {
    absl::string_view GetKeyFormatTypeName() const final {
      return "google.crypto.tink.JwtMlDsaKeyFormat";
    }

    absl::string_view GetPrivateKeyTypeName() const final {
      return "google.crypto.tink.JwtMlDsaPrivateKey";
    }

    absl::string_view GetPublicKeyTypeName() const final {
      return "google.crypto.tink.JwtMlDsaPublicKey";
    }

    std::unique_ptr<portable_proto::MessageLite>
    GetKeyFormatProtoDefaultInstance() const final {
      return absl::make_unique<google::crypto::tink::JwtMlDsaKeyFormat>();
    }

    std::unique_ptr<portable_proto::MessageLite>
    GetPrivateKeyProtoDefaultInstance() const final {
      return absl::make_unique<google::crypto::tink::JwtMlDsaPrivateKey>();
    }

    absl::StatusOr<std::unique_ptr<Key>> CreateKey(
        const Parameters& parameters) const final {
      const JwtMlDsaParameters* key_parameters =
          dynamic_cast<const JwtMlDsaParameters*>(&parameters);
      if (key_parameters == nullptr) {
        return absl::InternalError("Unexpected parameters type.");
      }
      return internal::CreateJwtMlDsaKey(*key_parameters,
                                         /*id_requirement=*/absl::nullopt);
    }
  };

  JwtMlDsaSignKeyManagerAdaptor()
      : key_factory_(std::make_unique<LegacyPrivateKeyFactoryImpl>(
            std::make_unique<PublicKeySignFactoryAdaptor>())) {}

  const std::string& GetKeyType() const final { return key_type_; }

  KeyMaterialTypeTP GetKeyMaterialType() const final {
    return KeyMaterialTypeTP::kAsymmetricPrivate;
  }

  const KeyFactory& GetKeyFactory() const final { return *key_factory_; }

  absl::StatusOr<std::unique_ptr<JwtPublicKeySignInternal>> GetPrimitive(
      const Key& key) const final {
    const JwtMlDsaPrivateKey* key_class =
        dynamic_cast<const JwtMlDsaPrivateKey*>(&key);
    if (key_class == nullptr) {
      return absl::InternalError("Unexpected key type.");
    }
    return jwt_internal::NewJwtMlDsaSignInternal(*key_class);
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom, "google.crypto.tink.JwtMlDsaPrivateKey");
  std::unique_ptr<KeyFactory> key_factory_;
};

}  // namespace

std::unique_ptr<KeyManager<JwtPublicKeySignInternal>>
MakeJwtMlDsaSignKeyManager() {
  return std::make_unique<LegacyKeyManagerImpl<JwtPublicKeySignInternal>>(
      std::make_unique<JwtMlDsaSignKeyManagerAdaptor>());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
