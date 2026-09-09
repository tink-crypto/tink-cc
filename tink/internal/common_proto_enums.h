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
#ifndef TINK_INTERNAL_COMMON_PROTO_ENUMS_H_
#define TINK_INTERNAL_COMMON_PROTO_ENUMS_H_

#include "absl/base/macros.h"
#include "proto/common.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {

using EllipticCurveTypeEnum
    [[deprecated("Use google::crypto::tink::internal::EllipticCurveType "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::EllipticCurveTypeTP;

[[deprecated(
    "Use google::crypto::tink::internal::EllipticCurveTypeTP_IsValid "
    "instead.")]]
ABSL_REFACTOR_INLINE inline bool EllipticCurveTypeEnumIsValid(int value) {
  return ::google::crypto::tink::internal::EllipticCurveTypeTP_IsValid(value);
}

using EcPointFormatEnum
    [[deprecated("Use google::crypto::tink::internal::EcPointFormat "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::EcPointFormatTP;

[[deprecated(
    "Use google::crypto::tink::internal::EcPointFormatTP_IsValid instead.")]]
ABSL_REFACTOR_INLINE inline bool EcPointFormatEnumIsValid(int c) {
  return ::google::crypto::tink::internal::EcPointFormatTP_IsValid(c);
}

using HashTypeEnum
    [[deprecated("Use google::crypto::tink::internal::HashType "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::HashTypeTP;

[[deprecated(
    "Use google::crypto::tink::internal::HashTypeTP_IsValid instead.")]]
ABSL_REFACTOR_INLINE inline bool HashTypeEnumIsValid(int c) {
  return ::google::crypto::tink::internal::HashTypeTP_IsValid(c);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_COMMON_PROTO_ENUMS_H_
