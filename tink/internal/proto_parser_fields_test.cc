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

#include "tink/internal/proto_parser_fields.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::StatusOr;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Test;

constexpr int32_t kUint32Field1Tag = 1;
constexpr int32_t kUint32Field2Tag = 2;
constexpr int32_t kBytesField1Tag = 3;
constexpr int32_t kBytesField2Tag = 4;
constexpr int32_t kUint32FieldWithLargeTag = 536870911;

struct ParsedStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
  std::string string_member_1;
  std::string string_member_2;
  SecretData secret_data_member_1;
  SecretData secret_data_member_2;
};

// Uint32Field ==============================================================
TEST(Uint32Field, ClearMemberWorks) {
  Uint32Field<ParsedStruct> field(kUint32Field1Tag,
                                  &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = 123;
  field.ClearMember(s);
  EXPECT_THAT(s.uint32_member_1, Eq(0));
}

TEST(Uint32Field, ConsumeIntoMemberSuccessCases) {
  Uint32Field<ParsedStruct> field(kUint32Field1Tag,
                                  &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = 999;

  for (std::pair<std::string, uint32_t> test_case :
       std::vector<std::pair<std::string, uint32_t>>{
           {"00", 0}, {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}}) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    absl::string_view serialized_view = serialized;
    EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), IsOk());
    EXPECT_THAT(s.uint32_member_1, Eq(test_case.second));
    EXPECT_THAT(serialized_view, IsEmpty());
  }
}

TEST(Uint32Field, ConsumeIntoMemberLeavesRemainingData) {
  Uint32Field<ParsedStruct> field(kUint32Field1Tag,
                                  &ParsedStruct::uint32_member_1);
  ParsedStruct s;
  s.uint32_member_1 = 999;
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  absl::string_view serialized_view = serialized;
  EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), IsOk());
  EXPECT_THAT(s.uint32_member_1, Eq(128));
  EXPECT_THAT(serialized_view, Eq("remaining data"));
}

TEST(Uint32Field, ConsumeIntoMemberFailureCases) {
  Uint32Field<ParsedStruct> field(kUint32Field1Tag,
                                  &ParsedStruct::uint32_member_1);
  ParsedStruct s;

  for (std::string test_case :
       {"", "8000", "8100", "faab",
        /* valid uint_64 encoding: */ "ffffffffffffffffff01"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    absl::string_view serialized_view = serialized;
    EXPECT_THAT(field.ConsumeIntoMember(serialized_view, s), Not(IsOk()));
  }
}

TEST(Uint32Field, GetTag) {
  Uint32Field<ParsedStruct> field(kUint32Field1Tag,
                                  &ParsedStruct::uint32_member_1);
  ASSERT_THAT(field.GetTag(), Eq(kUint32Field1Tag));
  Uint32Field<ParsedStruct> field2(kUint32Field2Tag,
                                   &ParsedStruct::uint32_member_2);
  ASSERT_THAT(field2.GetTag(), Eq(kUint32Field2Tag));
}

// StringBytesField ============================================================
TEST(StringBytesField, ClearMemberWorks) {
  StringBytesField<ParsedStruct> field(kBytesField1Tag,
                                       &ParsedStruct::string_member_1);
  ParsedStruct s;
  s.string_member_1 = "hello";
  field.ClearMember(s);
  EXPECT_THAT(s.string_member_1, Eq(""));
}

TEST(StringBytesField, ConsumeIntoMemberSuccessCases) {
  StringBytesField<ParsedStruct> field(kBytesField1Tag,
                                       &ParsedStruct::string_member_1);
  ParsedStruct s;
  s.string_member_1 = "hello";

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(s.string_member_1, Eq("1234567890"));
  EXPECT_THAT(bytes_view, Eq("XYZ"));
}

TEST(StringBytesField, ConsumeIntoMemberEmptyString) {
  StringBytesField<ParsedStruct> field(kBytesField1Tag,
                                       &ParsedStruct::string_member_1);
  ParsedStruct s;
  s.string_member_1 = "hello";

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(s.string_member_1, Eq(""));
  EXPECT_THAT(bytes_view, Eq("abcde"));
}

TEST(StringBytesField, EmptyWithoutVarint) {
  StringBytesField<ParsedStruct> field(kBytesField1Tag,
                                       &ParsedStruct::string_member_1);
  ParsedStruct s;

  std::string bytes = "";
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}

TEST(StringBytesField, InvalidVarint) {
  StringBytesField<ParsedStruct> field(kBytesField1Tag,
                                       &ParsedStruct::string_member_1);
  ParsedStruct s;

  std::string bytes = absl::StrCat(HexDecodeOrDie("8000"), "abcde");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}
// SecretDataBytesField ========================================================
TEST(SecretDataBytesField, ClearMemberWorks) {
  SecretDataBytesField<ParsedStruct> field(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1);
  ParsedStruct s;
  s.secret_data_member_1 = SecretDataFromStringView("hello");
  field.ClearMember(s);
  EXPECT_THAT(SecretDataAsStringView(s.secret_data_member_1), Eq(""));
}

TEST(SecretDataBytesField, ConsumeIntoMemberSuccessCases) {
  SecretDataBytesField<ParsedStruct> field(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1);
  ParsedStruct s;
  s.secret_data_member_1 = SecretDataFromStringView("hello");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(SecretDataAsStringView(s.secret_data_member_1), Eq("1234567890"));
  EXPECT_THAT(bytes_view, Eq("XYZ"));
}

TEST(SecretDataBytesField, ConsumeIntoMemberEmptyString) {
  SecretDataBytesField<ParsedStruct> field(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1);
  ParsedStruct s;
  s.secret_data_member_1 = SecretDataFromStringView("hello");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), IsOk());
  EXPECT_THAT(SecretDataAsStringView(s.secret_data_member_1), Eq(""));
  EXPECT_THAT(bytes_view, Eq("abcde"));
}

TEST(SecretDataBytesField, EmptyWithoutVarint) {
  SecretDataBytesField<ParsedStruct> field(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1);
  ParsedStruct s;

  std::string bytes = "";
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}

TEST(SecretDataBytesField, InvalidVarint) {
  SecretDataBytesField<ParsedStruct> field(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1);
  ParsedStruct s;

  std::string bytes = absl::StrCat(HexDecodeOrDie("8000"), "abcde");
  absl::string_view bytes_view = bytes;
  EXPECT_THAT(field.ConsumeIntoMember(bytes_view, s), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
