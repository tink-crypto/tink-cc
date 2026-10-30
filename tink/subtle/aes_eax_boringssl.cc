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

#include "tink/subtle/aes_eax_boringssl.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/internal/zero_copy_aes_eax_boringssl.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Aead>> AesEaxBoringSsl::New(
    const SecretData& key, size_t nonce_size_in_bytes) {
  ABSL_RETURN_IF_ERROR(internal::CheckFipsCompatibility<AesEaxBoringSsl>());
  if (key.size() != 16 && key.size() != 32) {
    return absl::InvalidArgumentError("Invalid key size");
  }
  if (nonce_size_in_bytes != 12 && nonce_size_in_bytes != 16) {
    return absl::InvalidArgumentError("Invalid nonce size");
  }
  ABSL_ASSIGN_OR_RETURN(AesEaxParameters parameters,
                        AesEaxParameters::Builder()
                            .SetKeySizeInBytes(key.size())
                            .SetIvSizeInBytes(nonce_size_in_bytes)
                            .SetTagSizeInBytes(16)
                            .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                            .Build());
  ABSL_ASSIGN_OR_RETURN(
      AesEaxKey aes_eax_key,
      AesEaxKey::Create(
          parameters, RestrictedData(key, InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  ABSL_ASSIGN_OR_RETURN(std::unique_ptr<internal::ZeroCopyAead> zero_copy_aead,
                        internal::AesEaxZeroCopyAead(aes_eax_key));
  return std::make_unique<internal::AeadFromZeroCopy>(
      std::move(zero_copy_aead));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
