// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/ml_dsa_verify_key_manager.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/legacy_key_manager_impl.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/constants.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

class MlDsaVerifyKeyManagerAdaptor
    : public LegacyKeyManagerAdaptor<PublicKeyVerify> {
 public:
  MlDsaVerifyKeyManagerAdaptor()
      : key_factory_(KeyFactory::AlwaysFailingFactory(absl::InternalError(
            "MlDsaVerifyKeyManager does not support key generation. Please use "
            "MlDsaSignKeyManager instead."))) {}

  const std::string& GetKeyType() const final { return key_type_; }

  KeyMaterialTypeTP GetKeyMaterialType() const final {
    return KeyMaterialTypeTP::kAsymmetricPublic;
  }

  const KeyFactory& GetKeyFactory() const final { return *key_factory_; }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> GetPrimitive(
      const Key& key) const final {
    const MlDsaPublicKey* key_class = dynamic_cast<const MlDsaPublicKey*>(&key);
    if (key_class == nullptr) {
      return absl::InternalError("Unexpected key type.");
    }
    return internal::NewMlDsaVerifyBoringSsl(*key_class);
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom, "google.crypto.tink.MlDsaPublicKey");
  std::unique_ptr<KeyFactory> key_factory_;
};

}  // namespace

std::unique_ptr<KeyManager<PublicKeyVerify>> MakeMlDsaVerifyKeyManager() {
  return std::make_unique<LegacyKeyManagerImpl<PublicKeyVerify>>(
      std::make_unique<MlDsaVerifyKeyManagerAdaptor>());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
