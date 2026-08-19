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
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/ec_util.h"

#include <cstdint>

#include "absl/status/statusor.h"
#include "tink/internal/ec_util.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<uint32_t> EcUtil::EncodingSizeInBytes(
    EllipticCurveType curve_type, EcPointFormat point_format) {
  return internal::EcPointEncodingSizeInBytes(curve_type, point_format);
}

uint32_t EcUtil::FieldSizeInBytes(EllipticCurveType curve_type) {
  absl::StatusOr<int32_t> size = internal::EcFieldSizeInBytes(curve_type);
  if (!size.ok()) {
    return 0;
  }
  return *size;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
