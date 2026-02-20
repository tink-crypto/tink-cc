// Copyright 2017 Google Inc.
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

#include "tink/signature/signature_config.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#include "tink/config/tink_fips.h"
#include "tink/registry.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "tink/signature/internal/ml_dsa_proto_serialization.h"
#include "tink/signature/internal/ml_dsa_sign_key_manager.h"
#include "tink/signature/internal/ml_dsa_verify_key_manager.h"
#include "tink/signature/internal/slh_dsa_proto_serialization.h"
#include "tink/signature/internal/slh_dsa_sign_key_manager.h"
#include "tink/signature/internal/slh_dsa_verify_key_manager.h"
#endif
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_proto_serialization.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

// static
absl::Status SignatureConfig::Register() {
  // Register primitive wrappers.
  auto status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>());
  if (!status.ok()) return status;
  status = Registry::RegisterPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>());
  if (!status.ok()) return status;

  // Register key managers which utilize FIPS validated BoringCrypto
  // implementations.
  // ECDSA
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<EcdsaSignKeyManager>(),
      absl::make_unique<EcdsaVerifyKeyManager>(), true);
  if (!status.ok()) return status;

  status = RegisterEcdsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }

  // RSA SSA PSS
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPssSignKeyManager>(),
      absl::make_unique<RsaSsaPssVerifyKeyManager>(), true);
  if (!status.ok()) return status;

  status = RegisterRsaSsaPssProtoSerialization();
  if (!status.ok()) return status;

  // RSA SSA PKCS1
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<RsaSsaPkcs1VerifyKeyManager>(), true);
  if (!status.ok()) return status;

  status = RegisterRsaSsaPkcs1ProtoSerialization();
  if (!status.ok()) return status;

  if (IsFipsModeEnabled()) {
    return absl::OkStatus();
  }

  // ED25519
  status = Registry::RegisterAsymmetricKeyManagers(
      absl::make_unique<Ed25519SignKeyManager>(),
      absl::make_unique<Ed25519VerifyKeyManager>(), true);
  if (!status.ok()) return status;

  status = RegisterEd25519ProtoSerialization();
  if (!status.ok()) return status;

  // Tink implements PQC signatures with BoringSSL, not OpenSSL.
#ifdef OPENSSL_IS_BORINGSSL
  // ML-DSA
  status =
      Registry::RegisterKeyManager(internal::MakeMlDsaSignKeyManager(), true);
  if (!status.ok()) return status;

  // Creating a new public key doesn't make sense and is therefore not allowed.
  status = Registry::RegisterKeyManager(internal::MakeMlDsaVerifyKeyManager(),
                                        false);
  if (!status.ok()) return status;

  status = RegisterMlDsaProtoSerialization();
  if (!status.ok()) return status;

  // SLH-DSA
  status =
      Registry::RegisterKeyManager(internal::MakeSlhDsaSignKeyManager(), true);
  if (!status.ok()) return status;

  // Creating a new public key doesn't make sense and is therefore not allowed.
  status = Registry::RegisterKeyManager(internal::MakeSlhDsaVerifyKeyManager(),
                                        false);
  if (!status.ok()) return status;

  status = RegisterSlhDsaProtoSerialization();
  if (!status.ok()) return status;
#endif

  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
