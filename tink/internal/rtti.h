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

#ifndef TINK_INTERNAL_RTTI_H_
#define TINK_INTERNAL_RTTI_H_

// Transitional forwarding header; include "third_party/tink/cc/rtti.h" and use
// `crypto::tink::{TypeIndex,GetStaticTypeIndex,GetTypeIndex,DynamicCast}`
// directly instead.

// IWYU pragma: begin_exports
#include "tink/rtti.h"
// IWYU pragma: end_exports

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::DynamicCast;
using ::crypto::tink::GetStaticTypeIndex;
using ::crypto::tink::GetTypeIndex;
using ::crypto::tink::TypeIndex;

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_RTTI_H_
