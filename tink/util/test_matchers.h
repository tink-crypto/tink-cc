// Copyright 2018 Google LLC
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

#ifndef TINK_UTIL_TEST_MATCHERS_H_
#define TINK_UTIL_TEST_MATCHERS_H_

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace test {
namespace internal {

template <typename T>
inline const absl::Status& GetStatus(const absl::StatusOr<T>& s) {
  return s.status();
}

inline const absl::Status& GetStatus(const absl::Status& s) { return s; }

}  // namespace internal

// Matches Status, StatusOr<>, or a reference to either of them, with the
// specified `code` as code().
MATCHER_P(StatusIs, code,
          "is a Status with a " + absl::StatusCodeToString(code) + " code") {
  const absl::Status& status = internal::GetStatus(arg);
  if (status.code() == code) {
    return true;
  }
  *result_listener << ::testing::PrintToString(status);
  return false;
}

// Matches Status, StatusOr<>, or a reference to either of them, whose code()
// equals `code`, and whose message() matches `message_macher`.
MATCHER_P2(StatusIs, code, message_matcher, "") {
  const absl::Status& status = internal::GetStatus(arg);
  return (status.code() == code) &&
         testing::Matches(message_matcher)(std::string(status.message()));
}

// Matches a Keyset::Key with `key`.
MATCHER_P(EqualsKey, key, "is equals to the expected key") {
  if (arg.key_id() == key.key_id() && arg.status() == key.status() &&
      arg.output_prefix_type() == key.output_prefix_type() &&
      arg.key_data().type_url() == key.key_data().type_url() &&
      arg.key_data().key_material_type() ==
          key.key_data().key_material_type() &&
      arg.key_data().value() == key.key_data().value()) {
    return true;
  }
  *result_listener << "Expected: " << arg.key_id() << ", "
                   << arg.output_prefix_type() << arg.key_data().type_url()
                   << ", " << arg.key_data().key_material_type() << ", "
                   << arg.key_data().value();
  *result_listener << "\nActual: " << key.key_id() << ", "
                   << key.output_prefix_type() << key.key_data().type_url()
                   << ", " << key.key_data().key_material_type() << ", "
                   << key.key_data().value();
  return false;
}

MATCHER_P(EqualsSecretData, data, "is equal to the expected secret data") {
  if (::crypto::tink::util::SecretDataEquals(arg, data)) {
    return true;
  }
  *result_listener << "Expected: "
                   << ::crypto::tink::util::SecretDataAsStringView(arg);
  *result_listener << "\nActual: "
                   << ::crypto::tink::util::SecretDataAsStringView(data);
  return false;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_TEST_MATCHERS_H_
