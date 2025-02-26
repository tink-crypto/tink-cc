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

#include "tink/prf/hmac_prf_parameters.h"

#include <set>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<HmacPrfParameters> HmacPrfParameters::Create(
    int key_size_in_bytes, HashType hash_type) {
  if (key_size_in_bytes < 16) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Key size must be at least 16 bytes, got ",
                                     key_size_in_bytes, " bytes."));
  }
  // Validate HashType.
  static const std::set<HashType>* supported_hashes = new std::set<HashType>(
      {HashType::kSha1, HashType::kSha224, HashType::kSha256, HashType::kSha384,
       HashType::kSha512});
  if (supported_hashes->find(hash_type) == supported_hashes->end()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create HmacPrf parameters with unknown HashType.");
  }
  return HmacPrfParameters(key_size_in_bytes, hash_type);
}

bool HmacPrfParameters::operator==(const Parameters& other) const {
  const HmacPrfParameters* that =
      dynamic_cast<const HmacPrfParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  return key_size_in_bytes_ == that->key_size_in_bytes_ &&
         hash_type_ == that->hash_type_;
}

}  // namespace tink
}  // namespace crypto
