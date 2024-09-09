// Copyright 2024 Google LLC
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

#include "tink/aead/x_aes_gcm_key_manager.h"

#include <cstdint>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/cord_x_aes_gcm_boringssl.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/internal/fips_utils.h"
#include "tink/subtle/random.h"
#include "tink/util/constants.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/tink.pb.h"
#include "proto/x_aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace {

constexpr int kCurrentVersion = 0;
constexpr int kKeySizeBytes = 32;

using ::crypto::tink::internal::FipsCompatibility;
using ::crypto::tink::subtle::Random;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::XAesGcmKey;
using ::google::crypto::tink::XAesGcmKeyFormat;
using ::google::crypto::tink::XAesGcmParams;

util::Status ValidateParams(const XAesGcmParams& params) {
  if (params.salt_size() < 8 || params.salt_size() > 12) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid salt size: ", params.salt_size()));
  }
  return absl::OkStatus();
}

util::Status ValidateKeySize(uint32_t key_size) {
  if (key_size != kKeySizeBytes) {
    return absl::InvalidArgumentError(
        absl::StrFormat("Invalid key size: %d, only %d bytes is supported.",
                        key_size, kKeySizeBytes));
  }
  return absl::OkStatus();
}

util::Status ValidateXAesGcmKey(const XAesGcmKey& key) {
  absl::Status status = ValidateKeySize(key.key_value().size());
  if (!status.ok()) {
    return status;
  }
  return ValidateParams(key.params());
}

class XAesGcmKeyManagerImpl
    : public KeyTypeManager<XAesGcmKey, XAesGcmKeyFormat, List<CordAead>> {
 public:
  class CordAeadFactory : public PrimitiveFactory<CordAead> {
    util::StatusOr<std::unique_ptr<CordAead>> Create(
        const XAesGcmKey& key) const override {
      util::Status status = ValidateXAesGcmKey(key);
      if (!status.ok()) {
        return status;
      }
      status = ValidateVersion(key.version(), kCurrentVersion);
      if (!status.ok()) {
        return status;
      }
      return internal::NewCordXAesGcmBoringSsl(
          util::SecretDataFromStringView(key.key_value()),
          key.params().salt_size());
    };
  };

  XAesGcmKeyManagerImpl()
      : KeyTypeManager(
            absl::make_unique<XAesGcmKeyManagerImpl::CordAeadFactory>()) {}

  uint32_t get_version() const override { return kCurrentVersion; }

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  util::Status ValidateKey(const XAesGcmKey& key) const override {
    util::Status status = ValidateVersion(key.version(), get_version());
    if (!status.ok()) {
      return status;
    }
    return ValidateXAesGcmKey(key);
  }

  util::Status ValidateKeyFormat(
      const XAesGcmKeyFormat& key_format) const override {
    util::Status status = ValidateParams(key_format.params());
    if (!status.ok()) {
      return status;
    }
    return ValidateVersion(key_format.version(), get_version());
  }

  util::StatusOr<XAesGcmKey> CreateKey(
      const XAesGcmKeyFormat& key_format) const override {
    util::Status status = ValidateKeyFormat(key_format);
    if (!status.ok()) {
      return status;
    }
    XAesGcmKey key;
    key.set_version(get_version());
    key.set_key_value(Random::GetRandomBytes(kKeySizeBytes));
    key.mutable_params()->set_salt_size(key_format.params().salt_size());
    return key;
  }

  util::StatusOr<XAesGcmKey> DeriveKey(
      const XAesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    return absl::UnimplementedError(
        "DeriveKey is not yet implemented for X-AES-GCM.");
  }

  FipsCompatibility FipsStatus() const override {
    return FipsCompatibility::kNotFips;
  }

 private:
  const std::string key_type_ =
      absl::StrCat(kTypeGoogleapisCom, XAesGcmKey().GetTypeName());
};

}  // namespace

std::unique_ptr<KeyTypeManager<XAesGcmKey, XAesGcmKeyFormat, List<CordAead>>>
CreateXAesGcmKeyManager() {
  return absl::make_unique<XAesGcmKeyManagerImpl>();
}

}  // namespace tink
}  // namespace crypto
