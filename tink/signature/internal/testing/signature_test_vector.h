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

#ifndef TINK_SIGNATURE_INTERNAL_TESTING_SIGNATURE_TEST_VECTOR_H_
#define TINK_SIGNATURE_INTERNAL_TESTING_SIGNATURE_TEST_VECTOR_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/signature/signature_private_key.h"

namespace crypto {
namespace tink {
namespace internal {

struct SignatureTestVector {
  SignatureTestVector(
      std::shared_ptr<SignaturePrivateKey> signature_private_key,
      absl::string_view signature, absl::string_view message)
      : signature_private_key(std::move(signature_private_key)),
        signature(signature),
        message(message) {}

  std::shared_ptr<SignaturePrivateKey> signature_private_key;
  std::string signature;
  std::string message;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_INTERNAL_TESTING_SIGNATURE_TEST_VECTOR_H_
