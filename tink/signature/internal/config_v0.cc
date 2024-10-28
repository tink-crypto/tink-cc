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

#include "tink/signature/internal/config_v0.h"
#include <memory>

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/signature/ed25519_verify_key_manager.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_proto_serialization.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/ed25519_sign_boringssl.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

util::StatusOr<std::unique_ptr<PublicKeySign>>
NewRsaSsaPkcs1SignBoringSsl(const RsaSsaPkcs1PrivateKey& key) {
  return crypto::tink::subtle::RsaSsaPkcs1SignBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
NewRsaSsaPkcs1VerifyBoringSsl(const RsaSsaPkcs1PublicKey& key) {
  return crypto::tink::subtle::RsaSsaPkcs1VerifyBoringSsl::New(key);
}


util::StatusOr<std::unique_ptr<PublicKeySign>>
NewRsaSsaPssSignBoringSsl(const RsaSsaPssPrivateKey& key) {
  return crypto::tink::subtle::RsaSsaPssSignBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
NewRsaSsaPssVerifyBoringSsl(const RsaSsaPssPublicKey& key) {
  return crypto::tink::subtle::RsaSsaPssVerifyBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeySign>>
NewEcdsaSignBoringSsl(const EcdsaPrivateKey& key) {
  return crypto::tink::subtle::EcdsaSignBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
NewEcdsaVerifyBoringSsl(const EcdsaPublicKey& key) {
  return crypto::tink::subtle::EcdsaVerifyBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeySign>>
NewEd25519SignBoringSsl(const Ed25519PrivateKey& key) {
  return crypto::tink::subtle::Ed25519SignBoringSsl::New(key);
}

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
NewEd25519VerifyBoringSsl(const Ed25519PublicKey& key) {
  return crypto::tink::subtle::Ed25519VerifyBoringSsl::New(key);
}

}  // namespace

util::Status AddSignatureV0(Configuration& config) {
  util::Status status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  // ECDSA
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<EcdsaSignKeyManager>(),
      absl::make_unique<EcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = RegisterEcdsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeySign,
                                                 EcdsaPrivateKey>(
      NewEcdsaSignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify,
                                                 EcdsaPublicKey>(
      NewEcdsaVerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  // Ed25519
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<Ed25519SignKeyManager>(),
      absl::make_unique<Ed25519VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = RegisterEd25519ProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeySign,
                                                 Ed25519PrivateKey>(
      NewEd25519SignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify,
                                                 Ed25519PublicKey>(
      NewEd25519VerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }

  // RSA SSA PKCS1
  status = ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPkcs1SignKeyManager>(),
      absl::make_unique<RsaSsaPkcs1VerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = RegisterRsaSsaPkcs1ProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeySign,
                                                 RsaSsaPkcs1PrivateKey>(
      NewRsaSsaPkcs1SignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify,
                                                 RsaSsaPkcs1PublicKey>(
      NewRsaSsaPkcs1VerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }

  // RSA SSA PSS
  status = RegisterRsaSsaPssProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeySign,
                                                 RsaSsaPssPrivateKey>(
      NewRsaSsaPssSignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status = ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify,
                                                 RsaSsaPssPublicKey>(
      NewRsaSsaPssVerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }

  return ConfigurationImpl::AddAsymmetricKeyManagers(
      absl::make_unique<RsaSsaPssSignKeyManager>(),
      absl::make_unique<RsaSsaPssVerifyKeyManager>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
