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

#include "tink/jwt/internal/jwt_ml_dsa_signature_config.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#include "tink/internal/fips_utils.h"
#include "tink/jwt/internal/jwt_ml_dsa_sign_key_manager.h"
#include "tink/jwt/internal/jwt_ml_dsa_verify_key_manager.h"
#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"
#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"
#include "tink/jwt/jwt_ml_dsa_proto_serialization.h"
#include "tink/registry.h"

namespace crypto {
namespace tink {
namespace internal {

// static
absl::Status JwtMlDsaSignatureRegister() {
  // Register primitive wrappers.
  absl::Status status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<jwt_internal::JwtPublicKeySignWrapper>());
  if (!status.ok()) {
    return status;
  }

  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<jwt_internal::JwtPublicKeyVerifyWrapper>());
  if (!status.ok()) {
    return status;
  }

  // TODO: b/485221516 - Move JWT ML-DSA key type above this check.
  if (IsFipsModeEnabled()) {
    return absl::OkStatus();
  }

  // Tink implements PQC signatures with BoringSSL, not OpenSSL.
#ifdef OPENSSL_IS_BORINGSSL
  // JWT ML-DSA
  status = RegisterJwtMlDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }

  status = Registry::RegisterKeyManager(internal::MakeJwtMlDsaSignKeyManager(),
                                        true);
  if (!status.ok()) {
    return status;
  }

  // Creating a new public key doesn't make sense and is therefore not allowed.
  status = Registry::RegisterKeyManager(
      internal::MakeJwtMlDsaVerifyKeyManager(), false);
  if (!status.ok()) {
    return status;
  }
#endif

  return absl::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
