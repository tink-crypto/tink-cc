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

#include "tink/internal/proto_parser_secret_data_owning_field.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/escaping.h"
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

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

absl::crc32c_t GetCrc32c(const SecretData& secret_data) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return absl::ComputeCrc32c(SecretDataAsStringView(secret_data));
#else
  return secret_data.GetCrc32c();
#endif
}

TEST(SecretDataOwningField, ClearMemberWorks) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("hello");
  field.Clear();
  EXPECT_THAT(field.value(), IsEmpty());
  EXPECT_THAT(GetCrc32c(field.value()), Eq(absl::crc32c_t{0}));
}

TEST(SecretDataOwningField, ConsumeIntoMemberWithCrcSuccessCases) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq("1234567890"));
  EXPECT_THAT(GetCrc32c(field.value()),
              Eq(absl::ComputeCrc32c("1234567890")));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
  EXPECT_THAT(crc_to_maintain, absl::ComputeCrc32c(bytes.substr(0, 11)));
}

TEST(SecretDataOwningField, ConsumeIntoMemberWithoutCrc) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq("1234567890"));
  EXPECT_THAT(GetCrc32c(field.value()),
              Eq(absl::ComputeCrc32c("1234567890")));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
}

TEST(SecretDataOwningField, ConsumeIntoMemberWithoutCrcEmptyString) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq(""));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
}

TEST(SecretDataOwningField, ConsumeIntoMemberWithCrcEmptyString) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq(""));
  EXPECT_THAT(GetCrc32c(field.value()), Eq(absl::crc32c_t{0}));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
  EXPECT_THAT(crc_to_maintain, absl::ComputeCrc32c(HexDecodeOrDie("00")));
}

// Tests that if the CRC is already populated, the field will just extend this.
TEST(SecretDataOwningField, ExistingCRCIsExtendedWhenParsing) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Existing");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  EXPECT_THAT(SecretDataAsStringView(field.value()), Eq("1234567890"));
  EXPECT_THAT(GetCrc32c(field.value()),
              Eq(absl::ComputeCrc32c("1234567890")));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
  EXPECT_THAT(crc_to_maintain,
              Eq(absl::ComputeCrc32c(absl::StrCat(
                  "Existing", HexDecodeOrDie("0a"), "1234567890"))));
}

TEST(SecretDataOwningField, SerializeEmptyWithoutCrcDoesntSerialize) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[0]));
}

TEST(SecretDataOwningField, SerializeEmptyWithCrcDoesntSerialize) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[0]));
  EXPECT_THAT(crc, Eq(absl::crc32c_t{}));
}

TEST(SecretDataOwningField, SerializeEmptyWithoutCrcAlwaysSerialize) {
  SecretDataOwningField field(1, ProtoFieldOptions::kAlwaysSerialize);
  *field.mutable_value() = SecretDataFromStringView("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(buffer.substr(0, 2), Eq(HexDecodeOrDie("0a00")));
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[2]));
}

TEST(SecretDataOwningField, SerializeEmptyWithCrcAlwaysSerialize) {
  SecretDataOwningField field(1, ProtoFieldOptions::kAlwaysSerialize);
  *field.mutable_value() = SecretDataFromStringView("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(buffer.substr(0, 2), Eq(HexDecodeOrDie("0a00")));
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[2]));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(HexDecodeOrDie("0a00"))));
}

TEST(SecretDataOwningField, SerializeNonEmptyWithCrc) {
  SecretDataOwningField field(1);
  std::string text = "this is some text";
  *field.mutable_value() = SecretDataFromStringView(text);

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag()]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text, "UFFER")));
  EXPECT_THAT(
      crc, Eq(absl::ComputeCrc32c(absl::StrCat(HexDecodeOrDie("0a11"), text))));
}

TEST(SecretDataOwningField, SerializeNonEmptyWithoutCrc) {
  SecretDataOwningField field(1);
  std::string text = "this is some text";
  *field.mutable_value() = SecretDataFromStringView(text);

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag()]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text, "UFFER")));
}

#if not TINK_CPP_SECRET_DATA_IS_STD_VECTOR
// Tests that when serializing a SecretDataOwningField, the resulting CRC
// is computed from the CRC of the field (and not the actual data).
TEST(SecretDataOwningField, CrcIsComputedFromCrc) {
  SecretDataOwningField field(1);
  std::string text1 = "this is some text";
  std::string text2 = "this is different";
  // The buffer is computed from a different value than the CRC.
  *field.mutable_value() = SecretData(text1, absl::ComputeCrc32c(text2));

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text1, "UFFER")));
  EXPECT_THAT(
      crc,
      Eq(absl::ComputeCrc32c(absl::StrCat(HexDecodeOrDie("0a11"), text2))));
}
#endif  // not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

TEST(SecretDataOwningField, SerializeTooSmallBuffer) {
  SecretDataOwningField field(1);
  std::string text = "this is some text";
  *field.mutable_value() = SecretDataFromStringView(text);

  std::string buffer = "BUFFERBUFFERBUFFE";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(SecretDataOwningField, SerializeMuchTooSmallBuffer) {
  SecretDataOwningField field(1);
  std::string text = "this is some text";
  *field.mutable_value() = SecretDataFromStringView(text);

  std::string buffer = "";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// Test that when serializing, the existing CRC in the state is extended by
// the new data (and not overwritten)
TEST(SecretDataOwningField, ExistingCrcIsExtended) {
  SecretDataOwningField field(1);
  std::string text = "this is some text";
  *field.mutable_value() = SecretDataFromStringView(text);

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc = absl::ComputeCrc32c("existing");
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag()));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag()]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text, "UFFER")));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(absl::StrCat(
                       "existing", HexDecodeOrDie("0a11"), text))));
}

TEST(SecretDataOwningField, ConsumeIntoMemberFailsWithNotEnoughDataForLength) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");
  // Varint indicates more data, but there is none.
  std::string bytes = HexDecodeOrDie("81");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(SecretDataOwningField,
     ConsumeIntoMemberFailsWithNotEnoughDataForContent) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");
  // 10 bytes length specified, but only 9 bytes available.
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "123456789");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(SecretDataOwningField, ConsumeIntoMemberFailsWithMalformedVarint) {
  SecretDataOwningField field(1);
  *field.mutable_value() = SecretDataFromStringView("before");
  // Varint is too long.
  std::string bytes = HexDecodeOrDie("ffffffff8f");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(SecretDataOwningField, SerializeTooSmallBufferForSizeVarint) {
  SecretDataOwningField field(1);
  // Size 128 requires 2 bytes for the varint encoding of the size.
  std::string text(128, 'a');
  *field.mutable_value() = SecretDataFromStringView(text);

  // Buffer is big enough for tag (1 byte) but not full size varint (2 bytes).
  std::string buffer = "BU";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
