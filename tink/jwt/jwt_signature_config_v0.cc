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

#include "tink/jwt/jwt_signature_config_v0.h"

#include "absl/log/check.h"
#include "tink/configuration.h"
#include "tink/jwt/internal/jwt_signature_config_v0.h"

namespace crypto {
namespace tink {

const Configuration& ConfigJwtSignatureV0() {
  static const Configuration* instance = [] {
    static Configuration* config = new Configuration();
    CHECK_OK(jwt_internal::AddJwtSignatureV0(*config));
    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
