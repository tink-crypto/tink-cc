// Copyright 2025 Google LLC
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
#include "tink/internal/tink_proto_structs.h"

#include <string_view>

#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {

std::string_view OutputPrefixTypeEnumName(
    ::google::crypto::tink::internal::OutputPrefixTypeTP type) {
  // Not named `OutputPrefixTypeTP`, to avoid the deprecated alias with that
  // name in this namespace.
  using PrefixType = ::google::crypto::tink::internal::OutputPrefixTypeTP;
  switch (type) {
    case PrefixType::kUnknownPrefix:
      return "UNKNOWN_PREFIX";
    case PrefixType::kTink:
      return "TINK";
    case PrefixType::kLegacy:
      return "LEGACY";
    case PrefixType::kRaw:
      return "RAW";
    case PrefixType::kCrunchy:
      return "CRUNCHY";
    case PrefixType::kWithIdRequirement:
      return "WITH_ID_REQUIREMENT";
  }
  // Values outside of the enum range are treated as unknown, consistent with
  // how the parser handles them.
  return "UNKNOWN_PREFIX";
}

std::string_view KeyMaterialTypeEnumName(
    ::google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP type) {
  // Not named `KeyMaterialTypeTP`, to avoid the deprecated alias with that
  // name in this namespace.
  using MaterialType =
      ::google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP;
  switch (type) {
    case MaterialType::kUnknownKeymaterial:
      return "UNKNOWN_KEYMATERIAL";
    case MaterialType::kSymmetric:
      return "SYMMETRIC";
    case MaterialType::kAsymmetricPrivate:
      return "ASYMMETRIC_PRIVATE";
    case MaterialType::kAsymmetricPublic:
      return "ASYMMETRIC_PUBLIC";
    case MaterialType::kRemote:
      return "REMOTE";
  }
  // Values outside of the enum range are treated as unknown, consistent with
  // how the parser handles them.
  return "UNKNOWN_KEYMATERIAL";
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
