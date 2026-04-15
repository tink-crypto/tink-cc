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

#ifndef TINK_SIGNATURE_INTERNAL_SLH_DSA_PARAMETER_SET_H_
#define TINK_SIGNATURE_INTERNAL_SLH_DSA_PARAMETER_SET_H_

#include "absl/status/statusor.h"
#include "tink/signature/slh_dsa_parameters.h"

namespace crypto {
namespace tink {
namespace internal {

class SlhDsaParameterSet {
 public:
  static SlhDsaParameterSet Sha2_128s();
  static SlhDsaParameterSet Shake_256f();

  SlhDsaParameters::HashType GetHashType() const { return hash_type_; }
  int GetPrivateKeySizeInBytes() const { return private_key_size_in_bytes_; }
  int GetPublicKeySizeInBytes() const { return private_key_size_in_bytes_ / 2; }
  SlhDsaParameters::SignatureType GetSignatureType() const {
    return signature_type_;
  }

  bool operator==(const SlhDsaParameterSet& other) const {
    return hash_type_ == other.hash_type_ &&
           private_key_size_in_bytes_ == other.private_key_size_in_bytes_ &&
           signature_type_ == other.signature_type_;
  }
  bool operator!=(const SlhDsaParameterSet& other) const {
    return !(*this == other);
  }

 private:
  explicit constexpr SlhDsaParameterSet(
      SlhDsaParameters::HashType hash_type, int private_key_size_in_bytes,
      SlhDsaParameters::SignatureType signature_type)
      : hash_type_(hash_type),
        private_key_size_in_bytes_(private_key_size_in_bytes),
        signature_type_(signature_type) {}

  SlhDsaParameters::HashType hash_type_;
  int private_key_size_in_bytes_;
  SlhDsaParameters::SignatureType signature_type_;
};

// Returns the parameter set from `params`. Fails if it is not a supported
// parameter set.
absl::StatusOr<SlhDsaParameterSet> GetSlhDsaParameterSet(
    const SlhDsaParameters& params);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_SLH_DSA_PARAMETER_SET_H_
