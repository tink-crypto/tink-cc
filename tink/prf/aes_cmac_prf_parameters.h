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

#ifndef TINK_PRF_AES_CMAC_PRF_PARAMETERS_H_
#define TINK_PRF_AES_CMAC_PRF_PARAMETERS_H_

#include <memory>
#include "tink/parameters.h"
#include "tink/prf/prf_parameters.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Describes the parameters of an `AesCmacPrfKey`.
class AesCmacPrfParameters : public PrfParameters {
 public:
  // Copyable and movable.
  AesCmacPrfParameters(const AesCmacPrfParameters& other) = default;
  AesCmacPrfParameters& operator=(const AesCmacPrfParameters& other) = default;
  AesCmacPrfParameters(AesCmacPrfParameters&& other) = default;
  AesCmacPrfParameters& operator=(AesCmacPrfParameters&& other) = default;

  // Creates an AES-CMAC-PRF parameters object. Returns an error status if
  // the key size is neither 16 nor 32 bytes.
  static absl::StatusOr<AesCmacPrfParameters> Create(int key_size_in_bytes);

  int KeySizeInBytes() const { return key_size_in_bytes_; }

  bool operator==(const Parameters& other) const override;

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<AesCmacPrfParameters>(*this);
  }

 private:
  explicit AesCmacPrfParameters(int key_size_in_bytes)
      : key_size_in_bytes_(key_size_in_bytes) {}

  int key_size_in_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_AES_CMAC_PRF_PARAMETERS_H_
