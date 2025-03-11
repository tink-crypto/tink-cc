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

#include "tink/internal/testing/field_with_number.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/testing/equals_proto_key_serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/restricted_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_testing {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;

constexpr absl::string_view kTypeUrl = "SomeArbitraryTypeUrl";

TEST(FieldWithNumberTest, Example) {
  ProtoKeySerialization serialization = SerializeMessage(
      kTypeUrl,
      {FieldWithNumber(1).IsVarint(10),
       FieldWithNumber(2).IsString(HexDecodeOrDie("aabbcc")),
       FieldWithNumber(3).IsSubMessage(
           {FieldWithNumber(1).IsVarint(7),
            FieldWithNumber(2).IsString(HexDecodeOrDie("889988998899"))}),
       FieldWithNumber(5).IsVarint(5)},
      KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
      /*id_requirement=*/12345);

  RestrictedData expected_key = RestrictedData(
      HexDecodeOrDie(absl::StrCat(/* field 1 */ "080a",
                                  /* field 2 */ "1203aabbcc",
                                  /* field 3 */ "1a0a",
                                  /* field 3.1 */ "0807",
                                  /* field 3.2 */ "1206889988998899",
                                  /* field 5 */ "2805")),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> expected =
      ProtoKeySerialization::Create(kTypeUrl, expected_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(expected.status(), IsOk());
  EXPECT_THAT(serialization, EqualsProtoKeySerialization(*expected));
}

}  // namespace proto_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
