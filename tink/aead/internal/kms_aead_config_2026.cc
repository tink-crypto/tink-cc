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

#include "tink/aead/internal/kms_aead_config_2026.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead/kms_aead_key_manager.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status AddKmsAead2026(Configuration& config) {
  absl::Status status = ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<KmsAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<KmsEnvelopeAeadKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
