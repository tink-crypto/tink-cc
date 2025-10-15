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

#include "tink/internal/proto_parser_repeated_secret_data_field.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
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
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::Test;

struct ParsedStruct {
  std::vector<SecretData> secret_data_vector;
};

absl::crc32c_t GetCrc32c(const SecretData& secret_data) {
#if TINK_CPP_SECRET_DATA_IS_STD_VECTOR
  return absl::ComputeCrc32c(SecretDataAsStringView(secret_data));
#else
  return secret_data.GetCrc32c();
#endif
}

TEST(RepeatedSecretDataBytesField, ClearMemberWorks) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("hello")});
  field.ClearMember(s);
  EXPECT_THAT(s.secret_data_vector, IsEmpty());
}

TEST(RepeatedSecretDataBytesField, ConsumeIntoMemberOneElementWorks) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("hello")});

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Previously parsed");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsTrue());
  // The existing member stays, we added a new one.
  EXPECT_THAT(s.secret_data_vector, SizeIs(2));
  EXPECT_THAT(SecretDataAsStringView(s.secret_data_vector[0]), Eq("hello"));
  EXPECT_THAT(SecretDataAsStringView(s.secret_data_vector[1]),
              Eq("1234567890"));
  EXPECT_THAT(crc_to_maintain,
              Eq(absl::ComputeCrc32c(absl::StrCat(
                  "Previously parsed", HexDecodeOrDie("0a"), "1234567890"))));
}

TEST(RepeatedSecretDataBytesField, ConsumeIntoMemberVarintSaysTooLong) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("hello")});

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0b"), "1234567890");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedSecretDataBytesField, EmptyWithoutVarint) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("hello")});

  std::string bytes = "";
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedSecretDataBytesField, InvalidVarint) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("hello")});

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsFalse());
}

TEST(RepeatedSecretDataBytesField, SerializeEmptyWithoutCrcDoesntSerialize) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector = std::vector<SecretData>();

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[0]));
}

TEST(RepeatedSecretDataBytesField, SerializeEmptySecretDataSerializes) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector = std::vector<SecretData>({SecretData()});

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[2]));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0a00"));
}

TEST(RepeatedSecretDataBytesField, SerializeMultipleSecretDatas) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector = std::vector<SecretData>(
      {SecretDataFromStringView("one"), SecretDataFromStringView("twotwo")});

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[13]));
  EXPECT_THAT(
      HexEncode(buffer.substr(0, 13)),
      Eq(absl::StrCat("0a03", HexEncode("one"), "0a06", HexEncode("twotwo"))));
}

#if not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

// Tests that when serializing a SecretDataField, the resulting CRC
// is computed from the CRC of the field (and not the actual data).
TEST(RepeatedSecretDataBytesField, CrcIsComputedFromCrc) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  std::string text1 = "this is some text";
  std::string text2 = "this is different";
  // The buffer is computed from a different value than the CRC.
  s.secret_data_vector =
      std::vector<SecretData>({SecretData(text1, absl::ComputeCrc32c(text2))});

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag(s)));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text1, "UFFER")));
  EXPECT_THAT(
      crc,
      Eq(absl::ComputeCrc32c(absl::StrCat(HexDecodeOrDie("0a11"), text2))));
}

#endif  // not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

TEST(RepeatedSecretDataBytesField, SerializeTooSmallBuffer) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector = std::vector<SecretData>(
      {SecretDataFromStringView("one"), SecretDataFromStringView("twotwo")});

  // Needs 13 bytes, see above
  std::string buffer = "123456789012";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

TEST(RepeatedSecretDataBytesField, SerializeTooSmallBuffer2) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("one")});

  std::string buffer = "0";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

TEST(RepeatedSecretDataBytesField, SerializeTooSmallBuffer3) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView("one")});

  std::string buffer = "";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state, s), Not(IsOk()));
}

// Test that when serializing, the existing CRC in the state is extended by
// the new data (and not overwritten)
TEST(RepeatedSecretDataBytesField, ExistingCrcIsExtended) {
  RepeatedSecretDataField<ParsedStruct> field(
      1, &ParsedStruct::secret_data_vector);
  ParsedStruct s;
  std::string text = "this is some text";
  s.secret_data_vector =
      std::vector<SecretData>({SecretDataFromStringView(text)});

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc = absl::ComputeCrc32c("existing");
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(s), Eq(19));
  ASSERT_THAT(field.SerializeWithTagInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSizeIncludingTag(s)));
  EXPECT_THAT(&(state.GetBuffer())[0],
              Eq(&buffer[field.GetSerializedSizeIncludingTag(s)]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("0a11"), text, "UFFER")));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(absl::StrCat(
                       "existing", HexDecodeOrDie("0a11"), text))));
}

TEST(OwningRepeatedSecretDataField, ClearWorks) {
  OwningRepeatedSecretDataField field(1);
  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Previously parsed");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  field.Clear();
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
}

TEST(OwningRepeatedSecretDataField, ConsumeOneElementWorks) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Previously parsed");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  ASSERT_THAT(field.value(), SizeIs(1));
  EXPECT_THAT(SecretDataAsStringView(field.value()[0]), Eq("1234567890"));

  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(12));
  EXPECT_THAT(crc_to_maintain,
              Eq(absl::ComputeCrc32c(absl::StrCat(
                  "Previously parsed", HexDecodeOrDie("0a"), "1234567890"))));

  std::string buffer(12, '\0');
  SerializationState serialization_state(absl::MakeSpan(buffer));
  ASSERT_THAT(field.SerializeWithTagInto(serialization_state), IsOk());
  EXPECT_THAT(HexEncode(buffer),
              Eq(absl::StrCat("0a0a", HexEncode("1234567890"))));
}

TEST(OwningRepeatedSecretDataField, ConsumeMultipleElementsWorks) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes1 = absl::StrCat(/* 3 bytes */ HexDecodeOrDie("03"), "one");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state1 = ParsingState(bytes1, &crc_to_maintain);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state1), IsTrue());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(5));

  std::string bytes2 =
      absl::StrCat(/* 6 bytes */ HexDecodeOrDie("06"), "twotwo");
  ParsingState parsing_state2 = ParsingState(bytes2, &crc_to_maintain);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state2), IsTrue());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(13));

  ASSERT_THAT(field.value(), SizeIs(2));
  EXPECT_THAT(SecretDataAsStringView(field.value()[0]), Eq("one"));
  EXPECT_THAT(SecretDataAsStringView(field.value()[1]), Eq("twotwo"));

  std::string buffer(13, '\0');
  SerializationState serialization_state(absl::MakeSpan(buffer));
  ASSERT_THAT(field.SerializeWithTagInto(serialization_state), IsOk());
  EXPECT_THAT(HexEncode(buffer), Eq(absl::StrCat("0a03", HexEncode("one"),
                                                 "0a06", HexEncode("twotwo"))));
}

TEST(OwningRepeatedSecretDataField, ConsumeVarintSaysTooLong) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes =
      absl::StrCat(/* 11 bytes */ HexDecodeOrDie("0b"), "1234567890");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
}

TEST(OwningRepeatedSecretDataField, ConsumeEmptyWithoutVarint) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes = "";
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
}

TEST(OwningRepeatedSecretDataField, ConsumeInvalidVarint) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
}

TEST(OwningRepeatedSecretDataField, SerializeEmptyDoesNotSerialize) {
  OwningRepeatedSecretDataField field(1);

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[0]));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
}

TEST(OwningRepeatedSecretDataField, SerializeEmptySecretDataWorks) {
  OwningRepeatedSecretDataField field(1);

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"));
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Previously parsed");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[2]));
  EXPECT_THAT(HexEncode(buffer.substr(0, 2)), Eq("0a00"));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
}

TEST(OwningRepeatedSecretDataField, SerializeMultipleSecretDatasWorks) {
  OwningRepeatedSecretDataField field(1);
  std::string text1 = "one";
  std::string text2 = "twotwo";
  field.value().push_back(SecretDataFromStringView(text1));
  field.value().push_back(SecretDataFromStringView(text2));

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(&state.GetBuffer()[0], Eq(&buffer[13]));
  EXPECT_THAT(
      HexEncode(buffer.substr(0, 13)),
      Eq(absl::StrCat("0a03", HexEncode("one"), "0a06", HexEncode("twotwo"))));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(13));
}

#if not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

// Tests that when serializing a SecretDataField, the resulting CRC
// is computed from the CRC of the field (and not the actual data).
TEST(OwningRepeatedSecretDataField, SerializeCrcIsComputedFromCrc) {
  OwningRepeatedSecretDataField field(1);
  std::string text1 = "this is some text";
  std::string text2 = "this is different";
  // The buffer is computed from a different value than the CRC.
  SecretData sd = SecretData(text1, absl::ComputeCrc32c(text2));
  field.value().push_back(sd);

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

TEST(OwningRepeatedSecretDataField, SerializeTooSmallBuffer) {
  OwningRepeatedSecretDataField field(1);
  std::string text1 = "one";
  std::string text2 = "twotwo";
  field.value().push_back(SecretDataFromStringView(text1));
  field.value().push_back(SecretDataFromStringView(text2));

  // Needs 13 bytes for serialization.
  std::string buffer = "123456789012";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(OwningRepeatedSecretDataField, SerializeTooSmallBuffer2) {
  OwningRepeatedSecretDataField field(1);
  std::string text1 = "one";
  std::string text2 = "twotwo";
  field.value().push_back(SecretDataFromStringView(text1));
  field.value().push_back(SecretDataFromStringView(text2));

  std::string buffer = "0";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(OwningRepeatedSecretDataField, SerializeTooSmallBuffer3) {
  OwningRepeatedSecretDataField field(1);
  std::string text1 = "one";
  std::string text2 = "twotwo";
  field.value().push_back(SecretDataFromStringView(text1));
  field.value().push_back(SecretDataFromStringView(text2));

  std::string buffer = "";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// Test that when serializing, the existing CRC in the state is extended by
// the new data (and not overwritten)
TEST(OwningRepeatedSecretDataField, SerializeExtendsExistingCrc) {
  OwningRepeatedSecretDataField field(1);
  std::string text = "this is some text";
  field.value().push_back(SecretDataFromStringView(text));

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

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
