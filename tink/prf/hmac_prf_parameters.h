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

#ifndef TINK_PRF_HMAC_PRF_PARAMETERS_H_
#define TINK_PRF_HMAC_PRF_PARAMETERS_H_

#include <memory>
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `HmacPrfKey`.
class HmacPrfParameters : public PrfParameters {
 public:
  // Describes the hash algorithm used.
  enum class HashType : int {
    kSha1 = 1,
    kSha224 = 2,
    kSha256 = 3,
    kSha384 = 4,
    kSha512 = 5,
    kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
  };

  // Copyable and movable.
  HmacPrfParameters(const HmacPrfParameters& other) = default;
  HmacPrfParameters& operator=(const HmacPrfParameters& other) = default;
  HmacPrfParameters(HmacPrfParameters&& other) = default;
  HmacPrfParameters& operator=(HmacPrfParameters&& other) = default;

  // Creates an HMAC-PRF parameters object. Key size must be at least 16 bytes.
  static util::StatusOr<HmacPrfParameters> Create(int key_size_in_bytes,
                                                  HashType hash_type);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  HashType GetHashType() const { return hash_type_; }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<HmacPrfParameters>(*this);
  }

 private:
  explicit HmacPrfParameters(int key_size_in_bytes, HashType hash_type)
      : key_size_in_bytes_(key_size_in_bytes), hash_type_(hash_type) {}

  int key_size_in_bytes_;
  HashType hash_type_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_HMAC_PRF_PARAMETERS_H_
