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

#include "tink/experimental/pqcrypto/signature/internal/key_creators.h"

#include <cstdint>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "openssl/experimental/spx.h"
#undef OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> CreateSlhDsaKey(
    const SlhDsaParameters& params, absl::optional<int> id_requirement) {
  uint8_t public_key_bytes[SPX_PUBLIC_KEY_BYTES];
  uint8_t private_key_bytes[SPX_SECRET_KEY_BYTES];

  SPX_generate_key(public_key_bytes, private_key_bytes);

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      params,
      absl::string_view(reinterpret_cast<const char*>(public_key_bytes),
                        SPX_PUBLIC_KEY_BYTES),
      id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  util::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(
          absl::string_view(reinterpret_cast<const char*>(private_key_bytes),
                            SPX_SECRET_KEY_BYTES),
          InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }

  return absl::make_unique<SlhDsaPrivateKey>(*private_key);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
