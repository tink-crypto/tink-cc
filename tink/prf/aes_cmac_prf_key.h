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

#ifndef TINK_PRF_AES_CMAC_PRF_KEY_H_
#define TINK_PRF_AES_CMAC_PRF_KEY_H_

#include <memory>
#include <utility>

#include "absl/status/statusor.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/prf_key.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents a PRF that uses AES-CMAC.
class AesCmacPrfKey final : public PrfKey {
 public:
  // Copyable and movable.
  AesCmacPrfKey(const AesCmacPrfKey& other) = default;
  AesCmacPrfKey& operator=(const AesCmacPrfKey& other) = default;
  AesCmacPrfKey(AesCmacPrfKey&& other) = default;
  AesCmacPrfKey& operator=(AesCmacPrfKey&& other) = default;

  // Creates a new AES-CMAC-PRF key.
  static absl::StatusOr<AesCmacPrfKey> Create(RestrictedData key_bytes,
                                              PartialKeyAccessToken token);

  const RestrictedData& GetKeyBytes(PartialKeyAccessToken token) const {
    return key_bytes_;
  }

  const AesCmacPrfParameters& GetParameters() const override {
    return parameters_;
  }

  bool operator==(const Key& other) const override;

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<AesCmacPrfKey>(*this);
  }

 private:
  AesCmacPrfKey(const AesCmacPrfParameters& parameters,
                RestrictedData key_bytes)
      : parameters_(parameters), key_bytes_(std::move(key_bytes)) {}

  AesCmacPrfParameters parameters_;
  RestrictedData key_bytes_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_AES_CMAC_PRF_KEY_H_
