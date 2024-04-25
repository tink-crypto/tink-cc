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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_TEST_UTIL_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_TEST_UTIL_H_

#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Generates a new SLH-DSA-SHA2-128s private key using the BoringSSL
// implementation.
util::StatusOr<SlhDsaPrivateKey> CreateSlhDsa128Sha2SmallSignaturePrivateKey(
    SlhDsaParameters::Variant variant, absl::optional<int> id_requirement);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_TEST_UTIL_H_
