// Copyright 2023 Google LLC
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

#include "tink/prf/key_gen_config_v0.h"

#include "absl/log/absl_check.h"
#include "tink/key_gen_configuration.h"
#include "tink/prf/internal/key_gen_config_v0.h"

namespace crypto {
namespace tink {

const KeyGenConfiguration& KeyGenConfigPrfV0() {
  static const KeyGenConfiguration* instance = [] {
    static KeyGenConfiguration* config = new KeyGenConfiguration();
    ABSL_CHECK_OK(internal::AddPrfKeyGenV0(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
