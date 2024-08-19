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

#include "tink/internal/proto_parser_enum_field.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

enum class MyEnum : uint32_t {
  k0 = 0,
  k1 = 1,
};

bool AlwaysValid(uint32_t v) { return true; }
bool IsZeroOrOne(uint32_t v) { return v == 0 || v == 1; }

struct ExampleStruct {
  MyEnum enum_field;
};

TEST(EnumField, ClearMemberWorks) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  s.enum_field = MyEnum::k1;
  field.ClearMember(s);
  EXPECT_THAT(s.enum_field, Eq(MyEnum::k0));
}

std::vector<std::pair<std::string, uint32_t>> GetUint32TestCases() {
  return std::vector<std::pair<std::string, uint32_t>>{
      {"00", 0}, {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}};
}

TEST(EnumField, ConsumeIntoMemberSuccessCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    absl::string_view serialized_view = serialized;
    EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), IsOk());
    EXPECT_THAT(s.enum_field, Eq(static_cast<MyEnum>(test_case.second)));
    EXPECT_THAT(serialized_view, IsEmpty());
  }
}

TEST(EnumField, ConsumeIntoMemberLeavesRemainingData) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  s.enum_field = static_cast<MyEnum>(999);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  absl::string_view serialized_view = serialized;
  EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), IsOk());
  EXPECT_THAT(s.enum_field, Eq(static_cast<MyEnum>(128)));
  EXPECT_THAT(serialized_view, Eq("remaining data"));
}

TEST(EnumField, ConsumeIntoMemberFailureCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::string test_case :
       {"", "8000", "8100", "faab",
        /* valid uint_64 encoding: */ "ffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    absl::string_view serialized_view = serialized;
    EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), Not(IsOk()));
  }
}

TEST(EnumField, ConsumeIntoMemberInvalidFails) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &IsZeroOrOne);
  ExampleStruct s;
  std::string serialized = HexDecodeOrDie("8001");
  absl::string_view serialized_view = serialized;
  EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), Not(IsOk()));
}

TEST(EnumField, SerializeVarintSuccessCases) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;

  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    s.enum_field = static_cast<MyEnum>(test_case.second);
    ASSERT_THAT(field.GetSerializedSize(s), Eq(test_case.first.size() / 2));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2);
    absl::Span<char> buffer_span = absl::MakeSpan(buffer);
    EXPECT_THAT(field.SerializeInto(buffer_span, s), IsOk());
    EXPECT_THAT(buffer, Eq(HexDecodeOrDie(test_case.first)));
    EXPECT_THAT(buffer_span.size(), Eq(0));
  }
}

TEST(EnumField, SerializeVarintBufferTooSmall) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  for (std::pair<std::string, uint32_t> test_case : GetUint32TestCases()) {
    SCOPED_TRACE(test_case.first);
    s.enum_field = static_cast<MyEnum>(test_case.second);
    ASSERT_THAT(field.GetSerializedSize(s), Eq(test_case.first.size() / 2));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2 - 1);
    absl::Span<char> buffer_span = absl::MakeSpan(buffer);
    EXPECT_THAT(field.SerializeInto(buffer_span, s), Not(IsOk()));
  }
}

TEST(EnumField, SerializeVarintLeavesRemainingData) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  std::string buffer = "abcdef";
  absl::Span<char> buffer_span = absl::MakeSpan(buffer);
  ExampleStruct s;
  s.enum_field = static_cast<MyEnum>(14882);
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeInto(buffer_span, s), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("a27463646566"));
  std::string expected = "cdef";
  // Note: absl::MakeSpan("cdef").size() == 5 (will add null terminator).
  EXPECT_THAT(buffer_span, Eq(absl::MakeSpan(expected)));
}

TEST(EnumField, GetTag) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ASSERT_THAT(field.GetTag(), Eq(1));
  EnumField<ExampleStruct, MyEnum> field2(2, &ExampleStruct::enum_field,
                                          &IsZeroOrOne);
  ASSERT_THAT(field2.GetTag(), Eq(2));
}

TEST(EnumField, RequiresSerialization) {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &AlwaysValid);
  ExampleStruct s;
  s.enum_field = MyEnum::k0;
  EXPECT_THAT(field.RequiresSerialization(s), Eq(false));
  s.enum_field = MyEnum::k1;
  EXPECT_THAT(field.RequiresSerialization(s), Eq(true));
}

bool NotZero(uint32_t v) { return v != 0; }

void DyingFunction() {
  EnumField<ExampleStruct, MyEnum> field(1, &ExampleStruct::enum_field,
                                         &NotZero);
  (void)field;
}
TEST(EnumFieldDeathTest, ZeroInvalidCrashes) {
  ASSERT_DEATH(DyingFunction(), "");
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto