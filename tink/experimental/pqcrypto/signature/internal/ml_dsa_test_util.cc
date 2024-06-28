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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/internal/ml_dsa_test_util.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "tink/restricted_data.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM
#include "openssl/experimental/dilithium.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<MlDsaPrivateKey> GenerateMlDsaPrivateKey(
    const MlDsaParameters& key_parameters, absl::optional<int> id_requirement) {
  if (key_parameters.GetInstance() != MlDsaParameters::Instance::kMlDsa65) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Only ML-DSA-65 is supported");
  }

  std::string public_key_bytes(DILITHIUM_PUBLIC_KEY_BYTES, '\0');
  auto private_key = util::MakeSecretUniquePtr<DILITHIUM_private_key>();
  DILITHIUM_generate_key(reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                         private_key.get());

  CBB cbb;
  size_t size;
  util::SecretData private_key_bytes(DILITHIUM_PRIVATE_KEY_BYTES);
  if (!CBB_init_fixed(&cbb, private_key_bytes.data(),
                      DILITHIUM_PRIVATE_KEY_BYTES) ||
      !DILITHIUM_marshal_private_key(&cbb, private_key.get()) ||
      !CBB_finish(&cbb, nullptr, &size) ||
      size != DILITHIUM_PRIVATE_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize ML-DSA private key");
  }

  util::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      key_parameters, public_key_bytes, id_requirement, GetPartialKeyAccess());

  return MlDsaPrivateKey::Create(*public_key,
                                 RestrictedData(std::move(private_key_bytes),
                                                InsecureSecretKeyAccess::Get()),
                                 GetPartialKeyAccess());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
