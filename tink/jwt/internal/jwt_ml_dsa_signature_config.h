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

#ifndef TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNATURE_CONFIG_H_
#define TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNATURE_CONFIG_H_

#include "absl/status/status.h"

namespace crypto {
namespace tink {
namespace internal {

// Registers JwtPublicKeySign and JwtPublicKeyVerify primitive wrapper and key
// managers for the JWT ML-DSA key type. This separate registration was only
// added to facilitate Python support. C++ API users should use
// tink/cc/jwt/jwt_signature_config_2026.h.
//
// TODO: b/485221516 - Merge into JwtSignatureRegister() with other key types.
absl::Status JwtMlDsaSignatureRegister();

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_ML_DSA_SIGNATURE_CONFIG_H_
