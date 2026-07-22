// Copyright 2026 Google LLC
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

#ifndef TINK_AEAD_INTERNAL_TESTING_AEAD_TEST_VECTOR_H_
#define TINK_AEAD_INTERNAL_TESTING_AEAD_TEST_VECTOR_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead/aead_key.h"

namespace crypto::tink::internal {

struct AeadTestVector {
  AeadTestVector(std::shared_ptr<AeadKey> aead_key, absl::string_view plaintext,
                 absl::string_view associated_data,
                 absl::string_view ciphertext)
      : aead_key(std::move(aead_key)),
        plaintext(plaintext),
        associated_data(associated_data),
        ciphertext(ciphertext) {}

  std::shared_ptr<AeadKey> aead_key;
  std::string plaintext;
  std::string associated_data;
  std::string ciphertext;
};

}  // namespace crypto::tink::internal

#endif  // TINK_AEAD_INTERNAL_TESTING_AEAD_TEST_VECTOR_H_
