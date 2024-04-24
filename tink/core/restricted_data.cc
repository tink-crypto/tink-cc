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

#include "tink/restricted_data.h"

#include <cstdint>

#include "absl/log/check.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {

RestrictedData::RestrictedData(int64_t num_random_bytes) {
  CHECK_GE(num_random_bytes, 0)
      << "Cannot generate a negative number of random bytes.\n";
  secret_ = subtle::Random::GetRandomKeyBytes(num_random_bytes);
}

}  // namespace tink
}  // namespace crypto
