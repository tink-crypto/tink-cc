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

#ifndef TINK_SIGNATURE_INTERNAL_ML_DSA_PEM_H_
#define TINK_SIGNATURE_INTERNAL_ML_DSA_PEM_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {

// Parses a given PEM serialized ML-DSA-44 public key `pem_serialized_key`
// into raw key bytes string.
absl::StatusOr<std::string> ParseMldsa44PublicKey(
    absl::string_view pem_serialized_key);

// Parses a given PEM serialized ML-DSA-65 public key `pem_serialized_key`
// into raw key bytes string.
absl::StatusOr<std::string> ParseMldsa65PublicKey(
    absl::string_view pem_serialized_key);

// Parses a given PEM serialized ML-DSA-87 public key `pem_serialized_key`
// into raw key bytes string.
absl::StatusOr<std::string> ParseMldsa87PublicKey(
    absl::string_view pem_serialized_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_ML_DSA_PEM_H_
