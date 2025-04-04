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

#ifndef TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_
#define TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_

#include <memory>

#include "tink/input_stream.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<crypto::tink::Key>> DeriveKey(
    const crypto::tink::Parameters& params,
    crypto::tink::InputStream* randomness);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_INTERNAL_KEY_DERIVERS_H_
