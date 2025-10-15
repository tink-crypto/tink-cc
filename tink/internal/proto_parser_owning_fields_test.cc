// Copyright 2025 Google LLC
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

#include "tink/internal/proto_parser_owning_fields.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
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
using ::crypto::tink::util::SecretDataAsStringView;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

constexpr int32_t kUint32Field1Number = 1;
constexpr int32_t kUint32Field2Number = 2;
constexpr int32_t kBytesField1Number = 3;

// Uint32Field ==============================================================
std::vector<std::pair<std::string, uint32_t>>
Uint32TestCasesParseAndSerialize() {
  return std::vector<std::pair<std::string, uint32_t>>{
      {"01", 1}, {"7f", 127}, {"8001", 128}, {"a274", 14882}};
}

std::vector<std::pair<std::string, uint32_t>> Uint32TestCasesParseOnly() {
  std::vector<std::pair<std::string, uint32_t>> result;
  result.push_back({"00", 0});
  // Padded up to 10 bytes.
  result.push_back({"8000", 0});
  result.push_back({"8100", 1});
  result.push_back({"fffffffffff100", 4294967295});
  result.push_back({"80808080808080808000", 0});
  result.push_back({"ffffffffffffffffff7f", 4294967295});
  return result;
}

TEST(Uint32Field, UninitializedValueIsZero) {
  Uint32OwningField field(kUint32Field1Number);
  EXPECT_THAT(field.value(), Eq(0));
}

TEST(Uint32Field, ClearWorks) {
  Uint32OwningField field(kUint32Field1Number);
  field.set_value(123);
  field.Clear();
  EXPECT_THAT(field.value(), Eq(0));
}

TEST(Uint32Field, ConsumeIntoMemberSuccessCases) {
  Uint32OwningField field(kUint32Field1Number);
  field.set_value(999);

  for (std::pair<std::string, uint32_t> test_case :
       Uint32TestCasesParseOnly()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
    EXPECT_THAT(field.value(), Eq(test_case.second));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(Uint32Field, ConsumeIntoMemberLeavesRemainingData) {
  Uint32OwningField field(kUint32Field1Number);
  field.set_value(999);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(Uint32Field, ConsumeIntoMemberFailureCases) {
  Uint32OwningField field(kUint32Field1Number);
  for (std::string test_case : {"", "faab"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  }
}

TEST(Uint32Field, SerializeVarintSuccessCases) {
  Uint32OwningField field(kUint32Field1Number);
  for (std::pair<std::string, uint32_t> test_case :
       Uint32TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie("08") + HexDecodeOrDie(test_case.first);
    field.set_value(test_case.second);
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
    EXPECT_THAT(HexEncode(buffer), Eq(HexEncode(expected_serialization)));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint32Field, SerializeVarintBufferTooSmall) {
  Uint32OwningField field(kUint32Field1Number);
  for (std::pair<std::string, uint32_t> test_case :
       Uint32TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    field.set_value(test_case.second);
    ASSERT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(test_case.first.size() / 2 + 1));

    std::string buffer;
    buffer.resize(test_case.first.size() / 2);
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
  }
}

TEST(Uint32Field, SerializeVarintLeavesRemainingData) {
  Uint32OwningField field(kUint32Field1Number);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(14882);
  // Will overwrite the first two bytes with 0xa274
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq("08a274646566"));
  std::string expected = "def";
  // Note: absl::MakeSpan("def").size() == 4 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint32Field, Empty) {
  Uint32OwningField field(kUint32Field1Number);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(0);

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "abcdef";
  // Note: absl::MakeSpan("abcdef").size() == 7 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint32Field, EmptyAlwaysSerialize) {
  Uint32OwningField field(kUint32Field1Number,
                          ProtoFieldOptions::kAlwaysSerialize);
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(0);

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "cdef";
  // Note: absl::MakeSpan("abcdef").size() == 7 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0800"));
}

TEST(Uint32Field, FieldNumber) {
  Uint32OwningField field(kUint32Field1Number);
  ASSERT_THAT(field.FieldNumber(), Eq(kUint32Field1Number));
  Uint32OwningField field2(kUint32Field2Number);
  ASSERT_THAT(field2.FieldNumber(), Eq(kUint32Field2Number));
}

// StringBytesField ============================================================
TEST(StringBytesField, ClearMemberWorks) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("hello");
  field.Clear();
  EXPECT_THAT(field.value(), Eq(""));
}

TEST(StringBytesField, ConsumeIntoMemberSuccessCases) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("hello");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq("1234567890"));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
}

TEST(StringBytesField, ConsumeIntoMemberEmptyString) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("hello");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq(""));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
}

TEST(StringBytesField, EmptyWithoutVarint) {
  OwningBytesField<std::string> field(kBytesField1Number);

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(StringBytesField, InvalidVarint) {
  OwningBytesField<std::string> field(kBytesField1Number);

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(StringBytesField, SerializeEmpty) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("");
  std::string buffer = "a";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(1));
}

TEST(StringBytesField, SerializeEmptyAlwaysSerialize) {
  OwningBytesField<std::string> field(kBytesField1Number,
                                      ProtoFieldOptions::kAlwaysSerialize);
  field.set_value("");
  std::string buffer = "ab";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  EXPECT_THAT(HexEncode(buffer), Eq("1a00"));
}

TEST(StringBytesField, SerializeNonEmpty) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag()]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("1a11"),
                                      "This is some text", "UFFER")));
}

TEST(StringBytesField, SerializeTooSmallBuffer) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer = "BUFFERBUFFERBUFF";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(StringBytesField, SerializeVerySmallBuffer) {
  OwningBytesField<std::string> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer;
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), Not(IsOk()));
}

// SecretDataBytesField ========================================================
TEST(SecretDataBytesField, ClearMemberWorks) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("hello");
  field.Clear();
  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq(""));
}

TEST(SecretDataBytesField, ConsumeIntoMemberSuccessCases) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("hello");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq("1234567890"));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
}

TEST(SecretDataBytesField, ConsumeIntoMemberEmptyString) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("hello");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq(""));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
}

TEST(SecretDataBytesField, EmptyWithoutVarint) {
  OwningBytesField<SecretData> field(kBytesField1Number);

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(SecretDataBytesField, InvalidVarint) {
  OwningBytesField<SecretData> field(kBytesField1Number);

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(SecretDataBytesField, SerializeEmpty) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("");
  std::string buffer = "a";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(1));
  EXPECT_THAT(HexEncode(buffer), Eq("61"));
}

TEST(SecretDataBytesField, SerializeEmptyAlwaysSerialize) {
  OwningBytesField<SecretData> field(kBytesField1Number,
                                     ProtoFieldOptions::kAlwaysSerialize);
  field.set_value("");
  std::string buffer = "ab";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  EXPECT_THAT(HexEncode(buffer), Eq("1a00"));
}

TEST(SecretDataBytesField, SerializeNonEmpty) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag()]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("1a11"),
                                      "This is some text", "UFFER")));
}

TEST(SecretDataBytesField, SerializeTooSmallBuffer) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer = "BUFFERBUFFERBUFF";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(SecretDataBytesField, SerializeVerySmallBuffer) {
  OwningBytesField<SecretData> field(kBytesField1Number);
  field.set_value("This is some text");
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
