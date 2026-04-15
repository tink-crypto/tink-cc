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

#include "tink/signature/internal/slh_dsa_parameter_set.h"

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/signature/slh_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

SlhDsaParameterSet SlhDsaParameterSet::Sha2_128s() {
  return SlhDsaParameterSet(SlhDsaParameters::HashType::kSha2, 64,
                            SlhDsaParameters::SignatureType::kSmallSignature);
}

SlhDsaParameterSet SlhDsaParameterSet::Shake_256f() {
  return SlhDsaParameterSet(SlhDsaParameters::HashType::kShake, 128,
                            SlhDsaParameters::SignatureType::kFastSigning);
}

namespace {
using SlhDsaParameterSetTuple = std::tuple<SlhDsaParameters::HashType, int,
                                           SlhDsaParameters::SignatureType>;
using SlhDsaParameterSetConstructor = SlhDsaParameterSet (*)();

const absl::flat_hash_map<SlhDsaParameterSetTuple,
                          SlhDsaParameterSetConstructor>&
GetParameterSetMap() {
  static const absl::NoDestructor<absl::flat_hash_map<
      SlhDsaParameterSetTuple, SlhDsaParameterSetConstructor>>
      kParameterSetMap = absl::NoDestructor<absl::flat_hash_map<
          SlhDsaParameterSetTuple, SlhDsaParameterSetConstructor>>({
          {{SlhDsaParameters::HashType::kSha2, 64,
            SlhDsaParameters::SignatureType::kSmallSignature},
           &SlhDsaParameterSet::Sha2_128s},
          {{SlhDsaParameters::HashType::kShake, 128,
            SlhDsaParameters::SignatureType::kFastSigning},
           &SlhDsaParameterSet::Shake_256f},
      });
  return *kParameterSetMap;
}
}  // namespace

absl::StatusOr<SlhDsaParameterSet> GetSlhDsaParameterSet(
    const SlhDsaParameters& params) {
  auto it = GetParameterSetMap().find({params.GetHashType(),
                                       params.GetPrivateKeySizeInBytes(),
                                       params.GetSignatureType()});
  if (it == GetParameterSetMap().end()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid SLH-DSA parameter combination. Only SLH-DSA-SHA2-128s and "
        "SLH-DSA-SHAKE-256f are supported.");
  }
  return (it->second)();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
