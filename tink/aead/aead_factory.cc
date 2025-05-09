// Copyright 2017 Google LLC
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

#include "tink/aead/aead_factory.h"

#include <memory>

#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/key_manager.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
// static
absl::StatusOr<std::unique_ptr<Aead>> AeadFactory::GetPrimitive(
    const KeysetHandle& keyset_handle) {
  absl::Status status =
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>());
  if (!status.ok()) {
    return status;
  }
  return keyset_handle.GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
}

// static
absl::StatusOr<std::unique_ptr<Aead>> AeadFactory::GetPrimitive(
    const KeysetHandle& keyset_handle,
    const KeyManager<Aead>* custom_key_manager) {
  absl::Status status =
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>());
  if (!status.ok()) {
    return status;
  }
  return keyset_handle.GetPrimitive<Aead>(custom_key_manager);
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

}  // namespace tink
}  // namespace crypto
