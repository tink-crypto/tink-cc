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

#include "tink/internal/proto_parser_secret_data_with_crc_field.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/secret_data_with_crc.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::SecretValue;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

struct ParsedStruct {
  SecretDataWithCrc secret_with_crc;
};

TEST(SecretDataWithCrcBytesField, ClearMemberWorks) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("hello");
  field.ClearMember(s);
  EXPECT_THAT(s.secret_with_crc.UncheckedData(),
              Eq(""));
  EXPECT_THAT(s.secret_with_crc.SecretCrc().value(), Eq(absl::crc32c_t{}));
}

TEST(SecretDataWithCrcBytesField, ConsumeIntoMemberSuccessCases) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsOk());

  EXPECT_THAT(s.secret_with_crc.UncheckedData(),
              Eq("1234567890"));
  EXPECT_THAT(s.secret_with_crc.SecretCrc().value(),
              Eq(absl::ComputeCrc32c("1234567890")));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
  EXPECT_THAT(crc_to_maintain, absl::ComputeCrc32c(bytes.substr(0, 11)));
}

TEST(SecretDataWithCrcBytesField, ConsumeIntoMemberRequiresStateWithCrc) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  ParsingState parsing_state = ParsingState(bytes);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
}

TEST(SecretDataWithCrcBytesField, ConsumeIntoMemberVarintSaysTooLong) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0b"), "1234567890");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
}

TEST(SecretDataWithCrcBytesField, ConsumeIntoMemberEmptyString) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes = absl::StrCat(/* 0 bytes */ HexDecodeOrDie("00"), "abcde");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsOk());

  EXPECT_THAT(s.secret_with_crc.UncheckedData(), Eq(""));
  EXPECT_THAT(s.secret_with_crc.SecretCrc().value(), Eq(absl::crc32c_t{0}));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("abcde"));
  EXPECT_THAT(crc_to_maintain, absl::ComputeCrc32c(HexDecodeOrDie("00")));
}

TEST(SecretDataWithCrcBytesField, EmptyWithoutVarint) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes = "";
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
}

TEST(SecretDataWithCrcBytesField, InvalidVarint) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  absl::crc32c_t crc_to_maintain = absl::crc32c_t{};
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), Not(IsOk()));
}

// Tests that if the CRC is already populated, the field will just extend this.
TEST(SecretDataWithCrcBytesField, ExistingCRCIsExtendedWhenParsing) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("before");

  std::string bytes =
      absl::StrCat(/* 10 bytes */ HexDecodeOrDie("0a"), "1234567890XYZ");
  absl::crc32c_t crc_to_maintain = absl::ComputeCrc32c("Existing");
  ParsingState parsing_state = ParsingState(bytes, &crc_to_maintain);

  EXPECT_THAT(field.ConsumeIntoMember(parsing_state, s), IsOk());

  EXPECT_THAT(s.secret_with_crc.UncheckedData(), Eq("1234567890"));
  EXPECT_THAT(s.secret_with_crc.SecretCrc().value(),
              Eq(absl::ComputeCrc32c("1234567890")));
  EXPECT_THAT(parsing_state.RemainingData(), Eq("XYZ"));
  EXPECT_THAT(crc_to_maintain,
              Eq(absl::ComputeCrc32c(absl::StrCat(
                  "Existing", HexDecodeOrDie("0a"), "1234567890"))));
}

TEST(SecretDataWithCrcBytesField, SerializeEmpty) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeInto(state, s), IsOk());
  EXPECT_THAT(buffer[0], Eq(0));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(HexDecodeOrDie("00"))));
}

TEST(SecretDataWithCrcBytesField, SerializeRequiresCrc) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("");

  std::string buffer = "BUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeInto(state, s), Not(IsOk()));
}

TEST(SecretDataWithCrcBytesField, SerializeNonEmpty) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  std::string text = "this is some text";
  s.secret_with_crc = SecretDataWithCrc(text);

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSize(s), Eq(18));
  ASSERT_THAT(field.SerializeInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSize(s)));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[field.GetSerializedSize(s)]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("11"), text, "BUFFER")));
  EXPECT_THAT(
      crc, Eq(absl::ComputeCrc32c(absl::StrCat(HexDecodeOrDie("11"), text))));
}

// Tests that when serializing a SecretDataWithCrcField, the resulting CRC
// is computed from the CRC of the field (and not the actual data).
TEST(SecretDataWithCrcBytesField, CrcIsComputedFromCrc) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  std::string text1 = "this is some text";
  std::string text2 = "this is different";
  // The buffer is computed from a different value than the CRC.
  s.secret_with_crc = SecretDataWithCrc(
      text1, SecretValue<absl::crc32c_t>(absl::ComputeCrc32c(text2)));

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSize(s), Eq(18));
  ASSERT_THAT(field.SerializeInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSize(s)));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("11"), text1, "BUFFER")));
  EXPECT_THAT(
      crc, Eq(absl::ComputeCrc32c(absl::StrCat(HexDecodeOrDie("11"), text2))));
}

TEST(SecretDataWithCrcBytesField, SerializeTooSmallBuffer) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  std::string text = "this is some text";
  s.secret_with_crc = SecretDataWithCrc(text);

  std::string buffer = "BUFFERBUFFERBUFFE";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeInto(state, s), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(SecretDataWithCrcBytesField, SerializeMuchTooSmallBuffer) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  std::string text = "this is some text";
  s.secret_with_crc = SecretDataWithCrc(text);

  std::string buffer = "";
  absl::crc32c_t crc{};
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.SerializeInto(state, s), Not(IsOk()));
}

// Test that when serializing, the existing CRC in the state is extended by
// the new data (and not overwritten)
TEST(SecretDataWithCrcBytesField, ExistingCrcIsExtended) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  std::string text = "this is some text";
  s.secret_with_crc = SecretDataWithCrc(text);

  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  absl::crc32c_t crc = absl::ComputeCrc32c("existing");
  SerializationState state = SerializationState(absl::MakeSpan(buffer), &crc);
  EXPECT_THAT(field.GetSerializedSize(s), Eq(18));
  ASSERT_THAT(field.SerializeInto(state, s), IsOk());
  EXPECT_THAT(state.GetBuffer().size(),
              Eq(buffer.size() - field.GetSerializedSize(s)));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[field.GetSerializedSize(s)]));
  EXPECT_THAT(buffer, Eq(absl::StrCat(HexDecodeOrDie("11"), text, "BUFFER")));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(
                       absl::StrCat("existing", HexDecodeOrDie("11"), text))));
}

TEST(SecretDataWithCrcBytesField, RequiresSerialization) {
  SecretDataWithCrcField<ParsedStruct> field(1, &ParsedStruct::secret_with_crc);
  ParsedStruct s;
  s.secret_with_crc = SecretDataWithCrc("");
  EXPECT_THAT(field.RequiresSerialization(s), IsFalse());
  s.secret_with_crc = SecretDataWithCrc("this is some text");
  EXPECT_THAT(field.RequiresSerialization(s), IsTrue());
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
