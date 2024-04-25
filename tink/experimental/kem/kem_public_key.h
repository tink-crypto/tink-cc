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

#ifndef TINK_EXPERIMENTAL_KEM_KEM_PUBLIC_KEY_H_
#define TINK_EXPERIMENTAL_KEM_KEM_PUBLIC_KEY_H_

#include "absl/strings/string_view.h"
#include "tink/experimental/kem/kem_parameters.h"
#include "tink/key.h"

namespace crypto {
namespace tink {

// Represents the public key of a key encapsulation mechanism.
class KemPublicKey : public Key {
 public:
  // Returns the bytes prefixed to every encapsulation generated by this key.
  //
  // In order to make key encapsulation unambiguous in the case of key rotation,
  // Tink requires every KEM public key to have an associated KEM output prefix.
  // When decapsulating a KEM ciphertext, only keys with a matching prefix have
  // to be tried.
  //
  // See https://developers.google.com/tink/wire-format#tink_output_prefix for
  // more background information on Tink output prefixes.
  virtual absl::string_view GetOutputPrefix() const = 0;

  const KemParameters& GetParameters() const override = 0;

  bool operator==(const Key& other) const override = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_KEM_KEM_PUBLIC_KEY_H_
