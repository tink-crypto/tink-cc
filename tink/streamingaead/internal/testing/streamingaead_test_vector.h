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

#ifndef TINK_STREAMINGAEAD_INTERNAL_TESTING_STREAMINGAEAD_TEST_VECTOR_H_
#define TINK_STREAMINGAEAD_INTERNAL_TESTING_STREAMINGAEAD_TEST_VECTOR_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/streamingaead/streaming_aead_key.h"

namespace crypto {
namespace tink {
namespace internal {

struct StreamingAeadTestVector {
  StreamingAeadTestVector(std::shared_ptr<StreamingAeadKey> streamingaead_key,
                          absl::string_view plaintext,
                          absl::string_view associated_data,
                          absl::string_view ciphertext)
      : streamingaead_key(std::move(streamingaead_key)),
        plaintext(plaintext),
        associated_data(associated_data),
        ciphertext(ciphertext) {}

  std::shared_ptr<StreamingAeadKey> streamingaead_key;
  std::string plaintext;
  std::string associated_data;
  std::string ciphertext;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMINGAEAD_INTERNAL_TESTING_STREAMINGAEAD_TEST_VECTOR_H_
