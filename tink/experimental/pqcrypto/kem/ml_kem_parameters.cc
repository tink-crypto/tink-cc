// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<MlKemParameters> MlKemParameters::Create(int key_size,
                                                        Variant variant) {
  if (key_size != 768) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-KEM key size. Only 768 keys are "
                        "currently supported.");
  }

  if (variant != Variant::kTink) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ML-KEM parameters with unknown Variant.");
  }

  return MlKemParameters(key_size, variant);
}

bool MlKemParameters::operator==(const Parameters& other) const {
  const MlKemParameters* that = dynamic_cast<const MlKemParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return key_size_ == that->key_size_ && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
