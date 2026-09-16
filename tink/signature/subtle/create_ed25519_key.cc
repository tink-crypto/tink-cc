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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/subtle/create_ed25519_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/ed25519_key_creator.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<Ed25519PrivateKey> CreateEd25519PrivateKey(
    const Ed25519Parameters& parameters, std::optional<int> id_requirement) {
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<Ed25519PrivateKey> key,
                        internal::CreateEd25519Key(parameters, id_requirement));

  return std::move(*key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
