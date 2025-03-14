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

#include "tink/jwt/internal/jwt_hmac_key_manager.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/input_stream.h"
#include "tink/jwt/internal/jwt_mac_impl.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/internal/raw_jwt_hmac_key_manager.h"
#include "tink/mac.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtHmacKey;
using ::google::crypto::tink::JwtHmacKeyFormat;

absl::StatusOr<std::unique_ptr<JwtMacInternal>>
JwtHmacKeyManager::JwtMacFactory::Create(const JwtHmacKey& jwt_hmac_key) const {
  int tag_size;
  std::string algorithm;
  HashType hash_type;
  switch (jwt_hmac_key.algorithm()) {
    case google::crypto::tink::JwtHmacAlgorithm::HS256:
      hash_type = HashType::SHA256;
      tag_size = 32;
      algorithm = "HS256";
      break;
    case google::crypto::tink::JwtHmacAlgorithm::HS384:
      hash_type = HashType::SHA384;
      tag_size = 48;
      algorithm = "HS384";
      break;
    case google::crypto::tink::JwtHmacAlgorithm::HS512:
      hash_type = HashType::SHA512;
      tag_size = 64;
      algorithm = "HS512";
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unknown algorithm.");
  }
  absl::StatusOr<std::unique_ptr<Mac>> mac = subtle::HmacBoringSsl::New(
      util::Enums::ProtoToSubtle(hash_type), tag_size,
      util::SecretDataFromStringView(jwt_hmac_key.key_value()));
  if (!mac.ok()) {
    return mac.status();
  }
  absl::optional<std::string> custom_kid = absl::nullopt;
  if (jwt_hmac_key.has_custom_kid()) {
    custom_kid = jwt_hmac_key.custom_kid().value();
  }
  if (custom_kid.has_value()) {
    return jwt_internal::JwtMacImpl::RawWithCustomKid(*std::move(mac),
                                                      algorithm, *custom_kid);
  }
  return jwt_internal::JwtMacImpl::Raw(*std::move(mac), algorithm);
}

uint32_t JwtHmacKeyManager::get_version() const {
  return raw_key_manager_.get_version();
}

google::crypto::tink::KeyData::KeyMaterialType
JwtHmacKeyManager::key_material_type() const {
  return raw_key_manager_.key_material_type();
}

const std::string& JwtHmacKeyManager::get_key_type() const {
  return raw_key_manager_.get_key_type();
}

absl::StatusOr<JwtHmacKey> JwtHmacKeyManager::CreateKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format) const {
  return raw_key_manager_.CreateKey(jwt_hmac_key_format);
}

absl::StatusOr<JwtHmacKey> JwtHmacKeyManager::DeriveKey(
    const JwtHmacKeyFormat& jwt_hmac_key_format,
    InputStream* input_stream) const {
  return raw_key_manager_.DeriveKey(jwt_hmac_key_format, input_stream);
}

Status JwtHmacKeyManager::ValidateKey(const JwtHmacKey& key) const {
  return raw_key_manager_.ValidateKey(key);
}

Status JwtHmacKeyManager::ValidateKeyFormat(
    const JwtHmacKeyFormat& key_format) const {
  return raw_key_manager_.ValidateKeyFormat(key_format);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
