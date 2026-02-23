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

#include "tink/signature/internal/slh_dsa_key_creator.h"

#include <cstdint>
#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
// Every header in BoringSSL includes base.h, which in turn defines
// OPENSSL_IS_BORINGSSL. So we include this common header upfront here to
// "force" the definition of OPENSSL_IS_BORINGSSL in case BoringSSL is used.
#include "openssl/crypto.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/slhdsa.h"
#endif
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/signature/slh_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> CreateSlhDsaKey(
    const SlhDsaParameters& params, absl::optional<int> id_requirement) {
#ifndef OPENSSL_IS_BORINGSSL
  return absl::UnimplementedError(
      "SLH-DSA is only supported in BoringSSL builds.");
#else
  uint8_t public_key_bytes[SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES];
  uint8_t private_key_bytes[SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES];

  SLHDSA_SHA2_128S_generate_key(public_key_bytes, private_key_bytes);

  absl::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      params,
      absl::string_view(reinterpret_cast<const char*>(public_key_bytes),
                        SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES),
      id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(
          absl::string_view(reinterpret_cast<const char*>(private_key_bytes),
                            SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES),
          GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  if (!private_key.ok()) {
    return private_key.status();
  }

  return absl::make_unique<SlhDsaPrivateKey>(*private_key);
#endif  // OPENSSL_IS_BORINGSSL
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
