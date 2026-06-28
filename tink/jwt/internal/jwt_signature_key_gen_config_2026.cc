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

#include "tink/jwt/internal/jwt_signature_key_gen_config_2026.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/mldsa.h"
#endif
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/jwt/internal/jwt_ecdsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ecdsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_ml_dsa_key_creator.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_sign_key_manager.h"
#include "tink/jwt/internal/jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_proto_serialization.h"
#include "tink/key_gen_configuration.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

absl::Status AddJwtSignatureKeyGen2026(KeyGenConfiguration& config) {
  absl::Status status =
      internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
          absl::make_unique<JwtEcdsaSignKeyManager>(),
          absl::make_unique<JwtEcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<JwtRsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<JwtRsaSsaPssSignKeyManager>(),
      absl::make_unique<JwtRsaSsaPssVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }

  // Tink implements PQC signatures with BoringSSL, not OpenSSL.
#ifdef OPENSSL_IS_BORINGSSL
  // JWT ML-DSA
  status = RegisterJwtMlDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = internal::KeyGenConfigurationImpl::AddKeyCreator<JwtMlDsaParameters>(
      internal::CreateJwtMlDsaKey, config);
  if (!status.ok()) {
    return status;
  }
#endif

  return absl::OkStatus();
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
