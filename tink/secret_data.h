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

#ifndef TINK_SECRET_DATA_H_
#define TINK_SECRET_DATA_H_

#include <vector>  // IWYU pragma: keep

#include "tink/internal/sanitizing_allocator.h"  // IWYU pragma: keep
#include "tink/util/secret_data_internal_class.h"

namespace crypto {
namespace tink {

// Stores secret (sensitive) data and makes sure it's marked as such and
// destroyed in a safe way.
// This should be the first choice when handling key/key derived values.
//
// Example:
// class MyCryptoPrimitive {
//  public:
//   MyCryptoPrimitive(absl::string_view key_value) :
//     key_(crypto::tink::util::SecretDataFromStringView(key_value)) {}
//   [...]
//  private:
//   const crypto::tink::SecretData key_;
// }

// TINK-PENDING-REMOVAL-IN-3.0.0-START
#ifndef TINK_CPP_SECRET_DATA_IS_STD_VECTOR
#define TINK_CPP_SECRET_DATA_IS_STD_VECTOR 1
#endif
// TINK-PENDING-REMOVAL-IN-3.0.0-END

#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
using SecretData =
    std::vector<uint8_t,
                crypto::tink::util::internal::SanitizingAllocator<uint8_t>>;
#else
using SecretData = ::crypto::tink::util::internal::SecretDataInternalClass;
#endif

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SECRET_DATA_H_
