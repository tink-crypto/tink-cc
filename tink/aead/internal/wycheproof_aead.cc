// Copyright 2021 Google LLC
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
#include "tink/aead/internal/wycheproof_aead.h"

#include <string>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectors;

std::vector<WycheproofTestVector> ReadWycheproofTestVectors(
    absl::string_view file_name) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectors(std::string(file_name));
  ABSL_CHECK_OK(parsed_input.status());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  std::vector<WycheproofTestVector> test_vectors;
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    const auto& test_group_fields = test_group.struct_value().fields();
    for (const google::protobuf::Value& test :
         test_group_fields.at("tests").list_value().values()) {
      const auto& test_fields = test.struct_value().fields();
      test_vectors.push_back(WycheproofTestVector{
          test_fields.at("comment").string_value(),
          GetBytesFromHexValue(test_fields.at("key")),
          GetBytesFromHexValue(test_fields.at("iv")),
          GetBytesFromHexValue(test_fields.at("msg")),
          GetBytesFromHexValue(test_fields.at("ct")),
          GetBytesFromHexValue(test_fields.at("aad")),
          GetBytesFromHexValue(test_fields.at("tag")),
          absl::StrCat(test_fields.at("tcId").number_value()),
          test_fields.at("result").string_value(),
      });
    }
  }
  return test_vectors;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
