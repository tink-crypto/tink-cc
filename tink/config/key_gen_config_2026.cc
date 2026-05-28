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

#include "tink/config/key_gen_config_2026.h"

#include "absl/log/absl_check.h"
#include "tink/aead/internal/key_gen_config_2026.h"
#include "tink/daead/internal/key_gen_config_2026.h"
#include "tink/hybrid/internal/key_gen_config_2026.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyderivation/internal/key_gen_config_2026.h"
#include "tink/mac/internal/key_gen_config_2026.h"
#include "tink/prf/internal/key_gen_config_2026.h"
#include "tink/signature/internal/key_gen_config_2026.h"
#include "tink/streamingaead/internal/key_gen_config_2026.h"

namespace crypto {
namespace tink {

const KeyGenConfiguration& KeyGenConfig2026() {
  static const KeyGenConfiguration* instance = [] {
    static KeyGenConfiguration* config = new KeyGenConfiguration();
    ABSL_CHECK_OK(internal::AddMacKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddAeadKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddDeterministicAeadKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddStreamingAeadKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddHybridKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddPrfKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddSignatureKeyGen2026(*config));
    ABSL_CHECK_OK(internal::AddKeyDerivationKeyGen2026(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
