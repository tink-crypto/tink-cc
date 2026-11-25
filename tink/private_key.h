// Copyright 2023 Google LLC
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

#ifndef TINK_PRIVATE_KEY_H_
#define TINK_PRIVATE_KEY_H_

#include "tink/key.h"
#include "tink/rtti.h"

namespace crypto {
namespace tink {

// Represents a private key. Note that private keys in Tink always include the
// corresponding public key.
class PrivateKey : public Key {
 public:
  virtual const Key& GetPublicKey() const = 0;

 private:
  TINK_INTERNAL_RTTI_ADD_METHODS_DERIVED(Key);
  TINK_INTERNAL_RTTI_SET_TYPE_ID(3);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRIVATE_KEY_H_
