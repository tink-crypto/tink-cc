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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_KEYDERIVATION_KEY_DERIVATION_KEY_H_
#define TINK_KEYDERIVATION_KEY_DERIVATION_KEY_H_

#include "tink/key.h"
#include "tink/keyderivation/key_derivation_parameters.h"

namespace crypto {
namespace tink {

// Represents a key derivation function.
class KeyDerivationKey : public Key {
 public:
  const KeyDerivationParameters& GetParameters() const override = 0;

  bool operator==(const Key& other) const override = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_KEY_DERIVATION_KEY_H_
