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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_RAW_ENCAPSULATE_BORINGSSL_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_RAW_ENCAPSULATE_BORINGSSL_H_

#include <memory>

#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/kem/internal/raw_kem_encapsulate.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<RawKemEncapsulate>>
NewMlKemRawEncapsulateBoringSsl(MlKemPublicKey recipient_key);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_KEM_INTERNAL_ML_KEM_RAW_ENCAPSULATE_BORINGSSL_H_
