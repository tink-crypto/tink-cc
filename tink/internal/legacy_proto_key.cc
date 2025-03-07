// Copyright 2022 Google LLC
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

#include "tink/internal/legacy_proto_key.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::Status CheckKeyAccess(KeyMaterialTypeEnum key_material_type,
                            absl::optional<SecretKeyAccessToken> token) {
  if (key_material_type == KeyMaterialTypeEnum::kSymmetric ||
      key_material_type == KeyMaterialTypeEnum::kAsymmetricPrivate) {
    if (!token.has_value()) {
      return absl::Status(
          absl::StatusCode::kPermissionDenied,
          "Missing secret key access token for legacy proto key.");
    }
  }
  return absl::OkStatus();
}

}  // namespace

bool UnusableLegacyProtoParameters::operator==(const Parameters& other) const {
  const UnusableLegacyProtoParameters* that =
      dynamic_cast<const UnusableLegacyProtoParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return type_url_ == that->type_url_ &&
         output_prefix_type_ == that->output_prefix_type_;
}

absl::StatusOr<LegacyProtoKey> LegacyProtoKey::Create(
    ProtoKeySerialization serialization,
    absl::optional<SecretKeyAccessToken> token) {
  absl::Status access_check_status =
      CheckKeyAccess(serialization.GetKeyMaterialTypeEnum(), token);
  if (!access_check_status.ok()) {
    return access_check_status;
  }
  return LegacyProtoKey(serialization);
}

bool LegacyProtoKey::operator==(const Key& other) const {
  const LegacyProtoKey* that = dynamic_cast<const LegacyProtoKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return serialization_.EqualsWithPotentialFalseNegatives(that->serialization_);
}

absl::StatusOr<const ProtoKeySerialization*> LegacyProtoKey::Serialization(
    absl::optional<SecretKeyAccessToken> token) const {
  absl::Status access_check_status =
      CheckKeyAccess(serialization_.GetKeyMaterialTypeEnum(), token);
  if (!access_check_status.ok()) {
    return access_check_status;
  }
  return &serialization_;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
