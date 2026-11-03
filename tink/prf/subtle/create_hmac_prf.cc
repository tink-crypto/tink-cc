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
////////////////////////////////////////////////////////////////////////////////

#include "tink/prf/subtle/create_hmac_prf.h"

#include <cstdint>
#include <memory>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/mac/internal/stateful_hmac_boringssl.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/prf_set.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/prf_set_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

struct HashParams {
  HashType hash_type;
  uint32_t max_output_length;
};

absl::StatusOr<HashParams> GetHashParams(
    HmacPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacPrfParameters::HashType::kSha1:
      return HashParams{HashType::SHA1, 20};
    case HmacPrfParameters::HashType::kSha224:
      return HashParams{HashType::SHA224, 28};
    case HmacPrfParameters::HashType::kSha256:
      return HashParams{HashType::SHA256, 32};
    case HmacPrfParameters::HashType::kSha384:
      return HashParams{HashType::SHA384, 48};
    case HmacPrfParameters::HashType::kSha512:
      return HashParams{HashType::SHA512, 64};
    default:
      return absl::InvalidArgumentError("Unsupported hash type");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<Prf>> CreateHmacPrf(const HmacPrfKey& key) {
  ABSL_RETURN_IF_ERROR(internal::ChecksFipsCompatibility(
      internal::FipsCompatibility::kRequiresBoringCrypto));
  if (key.GetParameters().KeySizeInBytes() < 16) {
    return absl::InvalidArgumentError("Key size must be at least 16 bytes.");
  }
  ABSL_ASSIGN_OR_RETURN(HashParams hash_params,
                        GetHashParams(key.GetParameters().GetHashType()));
  return CreatePrfFromStatefulMacFactory(
      std::make_unique<internal::StatefulHmacBoringSslFactory>(
          hash_params.hash_type, hash_params.max_output_length,
          key.GetKeyBytes(GetPartialKeyAccess())
              .Get(InsecureSecretKeyAccess::Get())));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
