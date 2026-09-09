// Copyright 2025 Google LLC
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

#ifndef TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
#define TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_

#include "absl/base/macros.h"
#include "proto/hmac.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {

using HmacParamsTP
    [[deprecated("Use google::crypto::tink::internal::HmacParamsTP "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::HmacParamsTP;
using HmacKeyTP
    [[deprecated("Use google::crypto::tink::internal::HmacKeyTP "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::HmacKeyTP;
using HmacKeyFormatTP
    [[deprecated("Use google::crypto::tink::internal::HmacKeyFormatTP "
                 "instead.")]] ABSL_REFACTOR_INLINE =
        ::google::crypto::tink::internal::HmacKeyFormatTP;

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
