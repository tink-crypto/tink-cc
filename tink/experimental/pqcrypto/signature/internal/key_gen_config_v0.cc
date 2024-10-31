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

#include "tink/experimental/pqcrypto/signature/internal/key_gen_config_v0.h"

#include "tink/experimental/pqcrypto/signature/internal/key_creators.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_proto_serialization.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"
#include "tink/signature/internal/key_creators.h"
#include "tink/signature/internal/ml_dsa_proto_serialization.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace internal {

util::Status AddPqcSignatureKeyGenV0(KeyGenConfiguration& config) {
  // SLH-DSA
  util::Status status = RegisterSlhDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  status = KeyGenConfigurationImpl::AddKeyCreator<SlhDsaParameters>(
      CreateSlhDsaKey, config);
  if (!status.ok()) {
    return status;
  }
  status = RegisterMlDsaProtoSerialization();
  if (!status.ok()) {
    return status;
  }
  return KeyGenConfigurationImpl::AddKeyCreator<MlDsaParameters>(CreateMlDsaKey,
                                                                 config);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
