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

#include "tink/jwt/internal/jwt_signature_config_v0.h"

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

util::Status AddJwtSignatureV0(Configuration& config) {
  util::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<JwtPublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<JwtPublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtEcdsaSignKeyManager>(),
      absl::make_unique<JwtEcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<JwtRsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPssSignKeyManager>(),
      absl::make_unique<JwtRsaSsaPssVerifyKeyManager>(), config);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
