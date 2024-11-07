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

#ifndef TINK_HYBRID_INTERNAL_TESTING_HYBRID_TEST_VECTORS_H_
#define TINK_HYBRID_INTERNAL_TESTING_HYBRID_TEST_VECTORS_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/hybrid/hybrid_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

struct HybridTestVector {
  HybridTestVector(std::shared_ptr<HybridPrivateKey> hybrid_private_key,
                   absl::string_view plaintext, absl::string_view context_info,
                   absl::string_view ciphertext)
      : hybrid_private_key(std::move(hybrid_private_key)),
        plaintext(plaintext),
        context_info(context_info),
        ciphertext(ciphertext) {}

  std::shared_ptr<HybridPrivateKey> hybrid_private_key;
  std::string plaintext;
  std::string context_info;
  std::string ciphertext;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_TESTING_HYBRID_TEST_VECTORS_H_
