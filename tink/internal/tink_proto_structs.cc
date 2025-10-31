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

#include <cstddef>
#include <string_view>
#include <vector>

#include "absl/base/no_destructor.h"

namespace crypto {
namespace tink {
namespace internal {

std::string_view OutputPrefixTypeEnumName(OutputPrefixTypeEnum type) {
  static const absl::NoDestructor<std::vector<std::string_view>>
      kOutputPrefixTypeEnumNames{{
          "UNKNOWN_PREFIX",
          "TINK",
          "LEGACY",
          "RAW",
          "CRUNCHY",
          "WITH_ID_REQUIREMENT",
      }};
  return (*kOutputPrefixTypeEnumNames)[static_cast<size_t>(type)];
}

std::string_view KeyMaterialTypeEnumName(KeyMaterialTypeEnum type) {
  static const absl::NoDestructor<std::vector<std::string_view>>
      kKeyMaterialTypeEnumNames{{"UNKNOWN_KEYMATERIAL", "SYMMETRIC",
                                 "ASYMMETRIC_PRIVATE", "ASYMMETRIC_PUBLIC",
                                 "REMOTE"}};
  return (*kKeyMaterialTypeEnumNames)[static_cast<size_t>(type)];
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
