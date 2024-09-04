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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_TESTING_EQUALS_PROTO_KEY_SERIALIZATION_H_
#define TINK_INTERNAL_TESTING_EQUALS_PROTO_KEY_SERIALIZATION_H_

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_testing {

inline std::string ConvertOptionalIntToString(absl::optional<int> s) {
  return s ? absl::StrCat(*s) : "nullopt";
}

MATCHER_P(EqualsProtoKeySerialization, expected, "") {
  bool equals = true;
  std::vector<std::string> debug_str;
  if (expected.TypeUrl() != arg.TypeUrl()) {
    equals = false;
    debug_str.push_back(absl::StrCat("Type URLS differ, expected '",
                                     expected.TypeUrl(), "', got '",
                                     arg.TypeUrl(), "'"));
  }
  absl::string_view expected_key =
      expected.SerializedKeyProto().GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view arg_key =
      arg.SerializedKeyProto().GetSecret(InsecureSecretKeyAccess::Get());
  if (expected_key != arg_key) {
    equals = false;
    debug_str.push_back(absl::StrCat(
        "Keys differ, expected '", expected_key, "' (hex ",
        crypto::tink::test::HexEncode(expected_key), "), got '", arg_key,
        "' (hex ", crypto::tink::test::HexEncode(arg_key), ")"));
  }
  if (expected.KeyMaterialType() != arg.KeyMaterialType()) {
    equals = false;
    debug_str.push_back(absl::StrCat(
        "KeyMaterialTypes differ, expected ",
        KeyData_KeyMaterialType_Name(expected.KeyMaterialType()), ", got ",
        KeyData_KeyMaterialType_Name(arg.KeyMaterialType())));
  }
  if (expected.GetOutputPrefixType() != arg.GetOutputPrefixType()) {
    equals = false;
    debug_str.push_back(absl::StrCat(
        "OutputPrefixType differ, expected ",
        OutputPrefixType_Name(expected.GetOutputPrefixType()), ", got ",
        OutputPrefixType_Name(arg.GetOutputPrefixType())));
  }
  if (expected.IdRequirement() != arg.IdRequirement()) {
    equals = false;
    debug_str.push_back(absl::StrCat(
        "IDRequirements differ, expected ",
        ConvertOptionalIntToString(expected.IdRequirement()), ", got ",
        ConvertOptionalIntToString(arg.IdRequirement())));
  }

  *result_listener << absl::StrJoin(debug_str, ",\n");
  return equals;
}

}  // namespace proto_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_EQUALS_PROTO_KEY_SERIALIZATION_H_
