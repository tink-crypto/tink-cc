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

#include "tink/signature/slh_dsa_parameters.h"

#include <tuple>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

namespace {
const absl::flat_hash_set<std::tuple<SlhDsaParameters::HashType, int,
                                     SlhDsaParameters::SignatureType>>&
GetSupportedParameterSets() {
  static const absl::NoDestructor<absl::flat_hash_set<std::tuple<
      SlhDsaParameters::HashType, int, SlhDsaParameters::SignatureType>>>
      kSupportedParameterSets({
          // SLH-DSA-SHA2-128s
          {SlhDsaParameters::HashType::kSha2, 64,
           SlhDsaParameters::SignatureType::kSmallSignature},
          // SLH-DSA-SHAKE-256f
          {SlhDsaParameters::HashType::kShake, 128,
           SlhDsaParameters::SignatureType::kFastSigning},
      });
  return *kSupportedParameterSets;
}
}  // namespace

absl::StatusOr<SlhDsaParameters> SlhDsaParameters::Create(
    HashType hash_type, int private_key_size_in_bytes,
    SignatureType signature_type, Variant variant) {
  if (GetSupportedParameterSets().find(
          {hash_type, private_key_size_in_bytes, signature_type}) ==
      GetSupportedParameterSets().end()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid SLH-DSA parameter combination. Only SLH-DSA-SHA2-128s and "
        "SLH-DSA-SHAKE-256f are supported.");
  }

  // Validate Variant.
  if (variant != Variant::kTink && variant != Variant::kNoPrefix) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create SLH-DSA parameters with unknown Variant.");
  }
  return SlhDsaParameters(hash_type, private_key_size_in_bytes, signature_type,
                          variant);
}

bool SlhDsaParameters::operator==(const Parameters& other) const {
  const SlhDsaParameters* that = dynamic_cast<const SlhDsaParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return hash_type_ == that->hash_type_ &&
         private_key_size_in_bytes_ == that->private_key_size_in_bytes_ &&
         signature_type_ == that->signature_type_ && variant_ == that->variant_;
}

}  // namespace tink
}  // namespace crypto
