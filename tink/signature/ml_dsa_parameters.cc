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

#include "tink/signature/ml_dsa_parameters.h"

#include "absl/status/status.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<MlDsaParameters> MlDsaParameters::Create(Instance instance,
                                                        Variant variant) {
  if (instance != Instance::kMlDsa65) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-DSA instance. Only ML-DSA-65 keys are "
                        "currently supported.");
  }

  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create ML-DSA parameters with unknown Variant.");
  }

  return MlDsaParameters(instance, variant);
}

bool MlDsaParameters::operator==(const Parameters& other) const {
  const MlDsaParameters* that = dynamic_cast<const MlDsaParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return instance_ == that->instance_ && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
