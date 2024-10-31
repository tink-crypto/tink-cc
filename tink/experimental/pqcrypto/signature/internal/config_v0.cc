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

#include "tink/experimental/pqcrypto/signature/internal/config_v0.h"

#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/experimental/pqcrypto/signature/internal/slh_dsa_sign_boringssl.h"
#include "tink/experimental/pqcrypto/signature/internal/slh_dsa_verify_boringssl.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_proto_serialization.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
#include "tink/internal/configuration_impl.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/ml_dsa_proto_serialization.h"
#include "tink/signature/internal/ml_dsa_sign_boringssl.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/public_key_sign_wrapper.h"
#include "tink/signature/public_key_verify_wrapper.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddPqcSignatureV0(Configuration& config) {
  // SLH-DSA
  util::Status status = RegisterSlhDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeySign, SlhDsaPrivateKey>(
          NewSlhDsaSignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify, SlhDsaPublicKey>(
          NewSlhDsaVerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  // ML-DSA
  status = RegisterMlDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeySign, MlDsaPrivateKey>(
          NewMlDsaSignBoringSsl, config);
  if (!status.ok()) {
    return status;
  }
  status =
      ConfigurationImpl::AddPrimitiveGetter<PublicKeyVerify, MlDsaPublicKey>(
          NewMlDsaVerifyBoringSsl, config);
  if (!status.ok()) {
    return status;
  }

  status = ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeySignWrapper>(), config);
  if (!status.ok()) {
    return status;
  }
  return ConfigurationImpl::AddPrimitiveWrapper(
      absl::make_unique<PublicKeyVerifyWrapper>(), config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
