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

#include "tink/prf/subtle/create_hkdf_prf.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/prf_set.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/prf/hkdf_streaming_prf.h"
#include "tink/subtle/prf/prf_set_util.h"
#include "tink/subtle/prf/streaming_prf.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

absl::StatusOr<HashType> ToSubtleHashType(
    HkdfPrfParameters::HashType hash_type) {
  switch (hash_type) {
    case HkdfPrfParameters::HashType::kSha1:
      return HashType::SHA1;
    case HkdfPrfParameters::HashType::kSha256:
      return HashType::SHA256;
    case HkdfPrfParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return absl::InvalidArgumentError("Unsupported hash type");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<Prf>> CreateHkdfPrf(const HkdfPrfKey& key) {
  ABSL_ASSIGN_OR_RETURN(HashType hash_type,
                        ToSubtleHashType(key.GetParameters().GetHashType()));
  ABSL_ASSIGN_OR_RETURN(
      std::unique_ptr<StreamingPrf> streaming_prf,
      HkdfStreamingPrf::New(hash_type,
                            key.GetKeyBytes(GetPartialKeyAccess())
                                .Get(InsecureSecretKeyAccess::Get()),
                            key.GetParameters().GetSalt().value_or("")));
  return CreatePrfFromStreamingPrf(std::move(streaming_prf));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
