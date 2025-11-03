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

#ifndef TINK_INTERNAL_TESTING_FIELD_WITH_NUMBER_H_
#define TINK_INTERNAL_TESTING_FIELD_WITH_NUMBER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/absl_check.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/tink_proto_structs.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_testing {

// A class which can be used to construct serialized protobuf strings.
// Example:
//   ProtoKeySerialization serialization = SerializeMessage(
//       kTypeUrl,
//       {FieldWithNumber(1).IsVarint(10),
//        FieldWithNumber(2).IsString("hi"),
//        FieldWithNumber(3).IsSubMessage(
//            {FieldWithNumber(1).IsVarint(10),
//             FieldWithNumber(2).IsString("key material")}),
//        FieldWithNumber(5).IsVarint(10)},
//       KeyData::SYMMETRIC, OutputPrefixType::TINK, /*id_requirement=*/123);
class FieldWithNumber {
 public:
  // Not default constructible, not copyable, not movable.
  FieldWithNumber() = delete;
  // Not copyable or movable
  FieldWithNumber(const FieldWithNumber&) = delete;
  FieldWithNumber& operator=(const FieldWithNumber&) = delete;

  explicit FieldWithNumber(int field_number) : field_number_(field_number) {
    ABSL_CHECK_GT(field_number_, 0);
    ABSL_CHECK_LE(field_number_, 536870912);
  }

  std::string IsVarint(uint64_t v);
  std::string IsString(absl::string_view v);
  std::string IsSubMessage(const std::vector<std::string>& s);

 private:
  int field_number_;
};

ProtoKeySerialization SerializeMessage(
    absl::string_view type_url, const std::vector<std::string>& v,
    crypto::tink::internal::KeyMaterialTypeEnum key_material_type,
    crypto::tink::internal::OutputPrefixTypeEnum output_prefix_type,
    absl::optional<int> id_requirement);

}  // namespace proto_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_FIELD_WITH_NUMBER_H_
