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
///////////////////////////////////////////////////////////////////////////////

#include "tink/config/fips_140_2.h"

#include <memory>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/internal/aes_ctr_hmac_aead_proto_serialization_impl.h"
#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"
#include "tink/configuration.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/serialization_registry.h"
#include "tink/mac/hmac_key_manager.h"
#include "tink/mac/internal/chunked_mac_wrapper.h"
#include "tink/mac/internal/hmac_proto_serialization_impl.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/prf/hmac_prf_key_manager.h"
#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"
#include "tink/prf/prf_set_wrapper.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"

namespace crypto {
namespace tink {
namespace {

absl::Status AddMac(Configuration& config) {
  ABSL_ASSIGN_OR_RETURN(
      internal::SerializationRegistry * serialization_registry,
      internal::ConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(internal::RegisterHmacProtoSerializationWithRegistry(
      *serialization_registry));

  absl::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<MacWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<internal::ChunkedMacWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  return internal::ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<HmacKeyManager>(), config);
}

absl::Status AddAead(Configuration& config) {
  ABSL_ASSIGN_OR_RETURN(
      internal::SerializationRegistry * serialization_registry,
      internal::ConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(
      internal::RegisterAesCtrHmacAeadProtoSerializationWithRegistry(
          *serialization_registry));
  ABSL_RETURN_IF_ERROR(internal::RegisterAesGcmProtoSerializationWithRegistry(
      *serialization_registry));

  absl::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<AeadWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesCtrHmacAeadKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<AesGcmKeyManager>(), config);
}

absl::Status AddPrf(Configuration& config) {
  ABSL_ASSIGN_OR_RETURN(
      internal::SerializationRegistry * serialization_registry,
      internal::ConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(internal::RegisterHmacPrfProtoSerializationWithRegistry(
      *serialization_registry));

  absl::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<PrfSetWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  return internal::ConfigurationImpl::AddKeyTypeManager(
      std::make_unique<HmacPrfKeyManager>(), config);
}

absl::Status AddSignature(Configuration& config) {
  ABSL_ASSIGN_OR_RETURN(
      internal::SerializationRegistry * serialization_registry,
      internal::ConfigurationImpl::GetSerializationRegistry(config));
  ABSL_RETURN_IF_ERROR(internal::RegisterEcdsaProtoSerializationWithRegistry(
      *serialization_registry));
  ABSL_RETURN_IF_ERROR(
      internal::RegisterRsaSsaPssProtoSerializationWithRegistry(
          *serialization_registry));
  ABSL_RETURN_IF_ERROR(
      internal::RegisterRsaSsaPkcs1ProtoSerializationWithRegistry(
          *serialization_registry));

  absl::Status status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<PublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddPrimitiveWrapper(
      std::make_unique<PublicKeyVerifyWrapper>(), config);
  if (!status.ok()) {
    return status;
  }

  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<EcdsaSignKeyManager>(),
      std::make_unique<EcdsaVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  status = internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<RsaSsaPssSignKeyManager>(),
      std::make_unique<RsaSsaPssVerifyKeyManager>(), config);
  if (!status.ok()) {
    return status;
  }
  return internal::ConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<RsaSsaPkcs1SignKeyManager>(),
      std::make_unique<RsaSsaPkcs1VerifyKeyManager>(), config);
}

}  // namespace

const Configuration& ConfigFips140_2() {
  static const Configuration* instance = [] {
    internal::SetFipsRestricted();

    static Configuration* config = new Configuration();
    ABSL_CHECK_OK(AddMac(*config));
    ABSL_CHECK_OK(AddAead(*config));
    ABSL_CHECK_OK(AddPrf(*config));
    ABSL_CHECK_OK(AddSignature(*config));

    return config;
  }();
  return *instance;
}

}  // namespace tink
}  // namespace crypto
