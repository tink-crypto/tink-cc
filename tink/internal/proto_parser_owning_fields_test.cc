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

TEST(Uint32Field, CopyAndMove) {
  Uint32OwningField field1(kUint32Field1Number);
  field1.set_value(123);

  // Test copy constructor
  Uint32OwningField field_copy(field1);
  EXPECT_THAT(field_copy.FieldNumber(), Eq(kUint32Field1Number));
  EXPECT_THAT(field_copy.value(), Eq(123));

  // Test copy assignment
  Uint32OwningField field_assign(kUint32Field2Number);
  field_assign = field1;
  EXPECT_THAT(field_assign.FieldNumber(), Eq(kUint32Field1Number));
  EXPECT_THAT(field_assign.value(), Eq(123));

  // Test move constructor
  Uint32OwningField field_move(std::move(field1));
  EXPECT_THAT(field_move.FieldNumber(), Eq(kUint32Field1Number));
  EXPECT_THAT(field_move.value(), Eq(123));

  // Test move assignment
  Uint32OwningField field_move_assign(kUint32Field2Number);
  field_move_assign = std::move(field_copy);
  EXPECT_THAT(field_move_assign.FieldNumber(), Eq(kUint32Field1Number));
  EXPECT_THAT(field_move_assign.value(), Eq(123));
}

// Uint64Field ==============================================================

std::vector<std::pair<std::string, uint64_t>>
Uint64TestCasesParseAndSerialize() {
  return std::vector<std::pair<std::string, uint64_t>>{
      {"01", 1},
      {"7f", 127},
      {"8001", 128},
      {"a274", 14882},
      {"ffffffff0f", 0xffffffffLL},
      {"8080808010", 0x100000000LL},
      {"f0bdf3d589cf959a12", 0x123456789abcdef0LL},
      {"ffffffffffffffff7f", 0x7fffffffffffffffLL},
      {"ffffffffffffffffff01", 0xffffffffffffffffLL},
  };
}

std::vector<std::pair<std::string, uint64_t>> Uint64TestCasesParseOnly() {
  std::vector<std::pair<std::string, uint64_t>> result =
      Uint64TestCasesParseAndSerialize();
  result.push_back({"00", 0});
  // Padded up to 10 bytes.
  result.push_back({"8000", 0});
  result.push_back({"80808080808080808000", 0});
  result.push_back({"8100", 1});
  result.push_back({"ffffffffffffffffff0f", 0xFFFFFFFFFFFFFFFFLL});
  result.push_back({"ffffffffffffffffff7f", 0xFFFFFFFFFFFFFFFFLL});
  return result;
}

TEST(Uint64Field, ClearMemberWorks) {
  Uint64OwningField field{1};
  field.set_value(123);
  field.Clear();
  EXPECT_THAT(field.value(), testing::Eq(0));
}

TEST(Uint64Field, ConsumeIntoMemberSuccessCases) {
  Uint64OwningField field{1};
  field.set_value(999);

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseOnly()) {
    SCOPED_TRACE(test_case.first);
    std::string serialized = HexDecodeOrDie(test_case.first);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
    EXPECT_THAT(field.value(), Eq(test_case.second));
    EXPECT_THAT(parsing_state.RemainingData(), IsEmpty());
  }
}

TEST(Uint64Field, ConsumeIntoMemberLeavesRemainingData) {
  Uint64OwningField field{1};
  field.set_value(999);
  std::string serialized =
      absl::StrCat(HexDecodeOrDie("8001"), "remaining data");
  ParsingState parsing_state = ParsingState(serialized);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.value(), Eq(128));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining data"));
}

TEST(Uint64Field, ConsumeIntoMemberFailureCases) {
  Uint64OwningField field{1};

  for (std::string test_case : {"", "faab"}) {
    SCOPED_TRACE(test_case);
    std::string serialized = HexDecodeOrDie(test_case);
    ParsingState parsing_state = ParsingState(serialized);
    EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  }
}

TEST(Uint64Field, SerializeVarintSuccessCases) {
  Uint64OwningField field{1};

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie("08") + HexDecodeOrDie(test_case.first);
    field.set_value(test_case.second);
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
    EXPECT_THAT(HexEncode(buffer), Eq(HexEncode(expected_serialization)));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint64Field, SerializeVarintDifferentFieldNumberSuccessCases) {
  Uint64OwningField field{12345};

  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
    SCOPED_TRACE(test_case.first);
    std::string expected_serialization =
        HexDecodeOrDie("c88306") + HexDecodeOrDie(test_case.first);
    field.set_value(test_case.second);
    EXPECT_THAT(field.GetSerializedSizeIncludingTag(),
                Eq(expected_serialization.size()));

    std::string buffer;
    buffer.resize(expected_serialization.size());
    SerializationState state = SerializationState(absl::MakeSpan(buffer));
    EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
    EXPECT_THAT(HexEncode(buffer), Eq(HexEncode(expected_serialization)));
    EXPECT_THAT(state.GetBuffer().size(), Eq(0));
  }
}

TEST(Uint64Field, SerializeVarintBufferTooSmall) {
  Uint64OwningField field{1};
  for (std::pair<std::string, uint64_t> test_case :
       Uint64TestCasesParseAndSerialize()) {
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

TEST(Uint64Field, SerializeVarintLeavesRemainingData) {
  Uint64OwningField field{1};
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

TEST(Uint64Field, Empty) {
  Uint64OwningField field{1};
  std::string buffer = "abcdef";
  SerializationState buffer_span = SerializationState(absl::MakeSpan(buffer));
  field.set_value(0);

  ASSERT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(buffer_span), IsOk());
  std::string expected = "abcdef";
  // Note: absl::MakeSpan("abcdef").size() == 7 (will add null terminator).
  EXPECT_THAT(buffer_span.GetBuffer(), Eq(absl::MakeSpan(expected)));
}

TEST(Uint64Field, FieldNumber) {
  Uint64OwningField field{1};
  ASSERT_THAT(field.FieldNumber(), Eq(1));
  Uint64OwningField field2{123};
  ASSERT_THAT(field2.FieldNumber(), Eq(123));
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

TEST(StringBytesField, CopyAndMove) {
  OwningBytesField<std::string> field1(kBytesField1Number);
  field1.set_value("test_string");

  // Test copy constructor
  OwningBytesField<std::string> field_copy(field1);
  EXPECT_THAT(field_copy.FieldNumber(), Eq(kBytesField1Number));
  EXPECT_THAT(field_copy.value(), Eq("test_string"));

  // Test copy assignment
  OwningBytesField<std::string> field_assign(kUint32Field2Number);
  field_assign = field1;
  EXPECT_THAT(field_assign.FieldNumber(), Eq(kBytesField1Number));
  EXPECT_THAT(field_assign.value(), Eq("test_string"));

  // Test move constructor
  OwningBytesField<std::string> field_move(std::move(field1));
  EXPECT_THAT(field_move.FieldNumber(), Eq(kBytesField1Number));
  EXPECT_THAT(field_move.value(), Eq("test_string"));

  // Test move assignment
  OwningBytesField<std::string> field_move_assign(kUint32Field2Number);
  field_move_assign = std::move(field_copy);
  EXPECT_THAT(field_move_assign.FieldNumber(), Eq(kBytesField1Number));
  EXPECT_THAT(field_move_assign.value(), Eq("test_string"));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
