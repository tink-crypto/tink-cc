// Copyright 2024 Google LLC
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

#include "tink/aead/xchacha20_poly1305_key.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

absl::StatusOr<std::string> ComputeOutputPrefix(
    XChaCha20Poly1305Parameters::Variant variant,
    absl::optional<int> id_requirement) {
  switch (variant) {
    case XChaCha20Poly1305Parameters::Variant::kNoPrefix:
      return std::string("");  // Empty prefix.
    case XChaCha20Poly1305Parameters::Variant::kCrunchy:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "id requirement must have value with kCrunchy");
      }
      return internal::ComputeOutputPrefix(0, *id_requirement);
    case XChaCha20Poly1305Parameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::Status(absl::StatusCode::kInvalidArgument,
                            "id requirement must have value with kTink");
      }
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid variant: ", variant));
  }
}

}  // namespace

absl::StatusOr<XChaCha20Poly1305Key> XChaCha20Poly1305Key::Create(
    XChaCha20Poly1305Parameters::Variant variant,
    const RestrictedData& key_bytes, absl::optional<int> id_requirement,
    PartialKeyAccessToken token) {
  if (key_bytes.size() != 32) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "XChaCha20-Poly1305 key length must be 32 bytes");
  }
  if (variant != XChaCha20Poly1305Parameters::Variant::kNoPrefix &&
      !id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key without ID requirement with variant with ID "
        "requirement");
  }
  if (variant == XChaCha20Poly1305Parameters::Variant::kNoPrefix &&
      id_requirement.has_value()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create key with ID requirement with variant without ID "
        "requirement");
  }
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(variant);
  if (!parameters.ok()) {
    return parameters.status();
  }
  absl::StatusOr<std::string> output_prefix =
      ComputeOutputPrefix(variant, id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return XChaCha20Poly1305Key(*parameters, key_bytes, id_requirement,
                              *std::move(output_prefix));
}

bool XChaCha20Poly1305Key::operator==(const Key& other) const {
  const XChaCha20Poly1305Key* that =
      dynamic_cast<const XChaCha20Poly1305Key*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (GetParameters() != that->GetParameters()) {
    return false;
  }
  if (id_requirement_ != that->id_requirement_) {
    return false;
  }
  return key_bytes_ == that->key_bytes_;
}

}  // namespace tink
}  // namespace crypto
