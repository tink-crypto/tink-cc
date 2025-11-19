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
#include "tink/internal/proto_parser_message.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/proto_parser_enum_field.h"
#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_parser_secret_data_field.h"
#include "tink/internal/proto_parser_state.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

namespace {

using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

class InnerStruct final : public Message {
 public:
  InnerStruct() = default;

  InnerStruct(uint32_t uint32_member_1, uint32_t uint32_member_2) {
    uint32_member_1_.set_value(uint32_member_1);
    uint32_member_2_.set_value(uint32_member_2);
  }

  uint32_t uint32_member_1() const { return uint32_member_1_.value(); }
  void set_uint32_member_1(uint32_t value) {
    uint32_member_1_.set_value(value);
  }
  uint32_t uint32_member_2() const { return uint32_member_2_.value(); }
  void set_uint32_member_2(uint32_t value) {
    uint32_member_2_.set_value(value);
  }

  bool operator==(const InnerStruct& other) const {
    return uint32_member_1_.value() == other.uint32_member_1_.value() &&
           uint32_member_2_.value() == other.uint32_member_2_.value();
  }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{
        {&uint32_member_1_, &uint32_member_2_}}[i];
  }

  Uint32Field uint32_member_1_{1};
  Uint32Field uint32_member_2_{2};
};

class OuterStruct : public Message {
 public:
  const InnerStruct& inner_member() const { return inner_member_.value(); }
  InnerStruct* mutable_inner_member() { return inner_member_.mutable_value(); }

  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 1; }
  const Field* field(int i) const override {
    return std::array<const Field*, 1>{{&inner_member_}}[i];
  }

  MessageField<InnerStruct> inner_member_{1};
};

TEST(MessageTest, Clear) {
  OuterStruct s;
  s.mutable_inner_member()->set_uint32_member_1(123);
  s.mutable_inner_member()->set_uint32_member_2(456);
  s.Clear();
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0));
}

#if !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)

// Serializes a varint using a wrong CRC.
absl::Status SerializeVarintWrongCrc(uint64_t value,
                                     SerializationState& output) {
  const int size = VarintLength(value);
  ABSL_CHECK_GE(size, output.GetBuffer().size());
  absl::Span<char> output_buffer = output.GetBuffer();
  int i = 0;
  while (value >= 0x80) {
    output_buffer[i++] = (static_cast<char>(value) & 0x7f) | 0x80;
    value >>= 7;
  }
  output_buffer[i++] = static_cast<char>(value);
  output.AdvanceWithCrc(size, absl::crc32c_t{0xAAAA});
  return absl::OkStatus();
}

// A proto message with a field that serializes a varint using a wrong CRC.
//
// This is used to test that the CRC accumulated during serialization is used
// for the returned SecretData.
class Uint32FieldWrongCrc : public Field {
 public:
  explicit Uint32FieldWrongCrc(
      uint32_t field_number,
      ProtoFieldOptions options = ProtoFieldOptions::kNone)
      : Field(field_number, WireType::kVarint), field_(field_number, options) {}

  // Copyable and movable.
  Uint32FieldWrongCrc(const Uint32FieldWrongCrc&) = default;
  Uint32FieldWrongCrc& operator=(const Uint32FieldWrongCrc&) = default;
  Uint32FieldWrongCrc(Uint32FieldWrongCrc&&) noexcept = default;
  Uint32FieldWrongCrc& operator=(Uint32FieldWrongCrc&&) noexcept = default;

  void Clear() override { field_.Clear(); }
  bool ConsumeIntoMember(ParsingState& serialized) override {
    return field_.ConsumeIntoMember(serialized);
  }
  absl::Status SerializeWithTagInto(SerializationState& out) const override {
    // Skip check for requires serialization.
    absl::Status status = SerializeWireTypeAndFieldNumber(
        GetWireType(), field_.FieldNumber(), out);
    if (!status.ok()) {
      return status;
    }
    return SerializeVarintWrongCrc(field_.value(), out);
  }
  size_t GetSerializedSizeIncludingTag() const override {
    return field_.GetSerializedSizeIncludingTag();
  }

  void set_value(uint32_t value) { field_.set_value(value); }
  uint32_t value() const { return field_.value(); }

 private:
  Uint32Field field_;
};

class OuterProtoClassWithWrongCrc : public Message {
 public:
  const InnerStruct& inner_member() const { return inner_member_.value(); }
  InnerStruct* mutable_inner_member() { return inner_member_.mutable_value(); }
  uint32_t uint32_member() const { return uint32_member_.value(); }
  void set_uint32_member(uint32_t value) { uint32_member_.set_value(value); }

  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{{&inner_member_, &uint32_member_}}[i];
  }

  MessageField<InnerStruct> inner_member_{1};
  Uint32FieldWrongCrc uint32_member_{2};
};

TEST(MessageTest, SerializeAsSecretDataFails) {
  OuterProtoClassWithWrongCrc s;
  s.mutable_inner_member()->set_uint32_member_1(0x23);
  s.mutable_inner_member()->set_uint32_member_2(0x7a);
  s.set_uint32_member(0x7a);
  SecretData buffer = s.SerializeAsSecretData();
  EXPECT_THAT(
      util::SecretDataAsStringView(buffer),
      Eq(absl::StrJoin(
          {FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                            FieldWithNumber(2).IsVarint(0x7a)}),
           FieldWithNumber(2).IsVarint(0x7a)},
          "")));
  EXPECT_THAT(buffer.ValidateCrc32c(), Not(IsOk()));
}

#endif  // !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)

TEST(MessageTest, SerializeAsSecretDataSuccess) {
  OuterStruct s;
  s.mutable_inner_member()->set_uint32_member_1(0x23);
  s.mutable_inner_member()->set_uint32_member_2(0x7a);
  SecretData buffer = s.SerializeAsSecretData();
  EXPECT_THAT(
      util::SecretDataAsStringView(buffer),
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
#if !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
  EXPECT_THAT(buffer.ValidateCrc32c(), IsOk());
  EXPECT_THAT(buffer.GetCrc32c(),
              Eq(absl::ComputeCrc32c(s.SerializeAsString())));
#endif  // !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
}

TEST(MessageTest, SerializeAsStringSuccess) {
  OuterStruct s;
  s.mutable_inner_member()->set_uint32_member_1(0x23);
  s.mutable_inner_member()->set_uint32_member_2(0x7a);
  std::string buffer = s.SerializeAsString();
  EXPECT_THAT(
      buffer,
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
}

TEST(MessageTest, ParseFromStringSuccess) {
  std::string bytes =
      absl::StrCat(/* Size and tag */ HexDecodeOrDie("0a04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  OuterStruct s;
  s.Clear();
  EXPECT_TRUE(s.ParseFromString(bytes));
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0x7a));
}

struct OuterMessageWithSecretData : public Message {
 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{
        {&inner_member_field, &secret_data_field}}[i];
  }

 public:
  MessageField<InnerStruct> inner_member_field{1};
  SecretDataField secret_data_field{2};
};

TEST(MessageTest, ParseFromStringWithCrcSuccess) {
  std::string bytes = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                       FieldWithNumber(2).IsVarint(0x7a)}),
      FieldWithNumber(2).IsString("secret_data"));
  OuterMessageWithSecretData s;
  absl::StatusOr<util::SecretValue<absl::crc32c_t>> result_crc =
      s.ParseFromStringWithCrc(bytes);
  ASSERT_THAT(result_crc, IsOk());
  EXPECT_THAT(result_crc->value(), Eq(absl::ComputeCrc32c(bytes)));
  EXPECT_THAT(s.inner_member_field.value().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(s.inner_member_field.value().uint32_member_2(), Eq(0x7a));
  EXPECT_THAT(util::SecretDataAsStringView(s.secret_data_field.value()),
              Eq("secret_data"));
#if !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
  EXPECT_THAT(s.secret_data_field.value().ValidateCrc32c(), IsOk());
  EXPECT_THAT(s.secret_data_field.value().GetCrc32c(),
              Eq(absl::ComputeCrc32c("secret_data")));
#endif  // !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
}

TEST(MessageTest, SerializeAndParse) {
  OuterStruct s;
  s.mutable_inner_member()->set_uint32_member_1(0x23);
  s.mutable_inner_member()->set_uint32_member_2(0x7a);
  SecretData bytes = s.SerializeAsSecretData();
#if !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
  EXPECT_THAT(bytes.ValidateCrc32c(), IsOk());
  EXPECT_THAT(bytes.GetCrc32c(),
              Eq(absl::ComputeCrc32c(s.SerializeAsString())));
#endif  // !defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
  s.Clear();
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0));
  EXPECT_TRUE(s.ParseFromString(util::SecretDataAsStringView(bytes)));
  EXPECT_THAT(s.inner_member().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(s.inner_member().uint32_member_2(), Eq(0x7a));
}

TEST(MessageTest, ParseFromStringFails) {
  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"));
  bytes.resize(bytes.size() - 1);  // One byte too short.
  OuterStruct s;
  s.Clear();
  EXPECT_FALSE(s.ParseFromString(bytes));
}

// -----------------------------------------------------------------------------
// RepeatedMessageField tests.

TEST(RepeatedMessageField, ConsumeIntoMemberSuccessCases) {
  RepeatedMessageField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(0x23, 0x7a), InnerStruct(0x01, 0)));
}

TEST(RepeatedMessageField, ConsumeIntoMemberWithCrcSuccessCases) {
  RepeatedMessageField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      /* 2 bytes */ HexDecodeOrDie("02"),
      /* Int field, tag 1, value 0x01 */ HexDecodeOrDie("0801"),
      "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 8))));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(0x23, 0x7a), InnerStruct(0x01, 0)));
}

TEST(RepeatedMessageField, ConsumeIntoMemberEmptyString) {
  RepeatedMessageField<InnerStruct> field{1};
  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(field.values(), ElementsAre(InnerStruct()));
}

TEST(RepeatedMessageField, ConsumeIntoMemberAppends) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct(123, 456));
  std::string bytes = absl::StrCat(
      /* 4 bytes */ HexDecodeOrDie("04"),
      /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
      /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
      "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(field.values(),
              ElementsAre(InnerStruct(123, 456), InnerStruct(0x23, 0x7a)));
}

TEST(RepeatedMessageField, ConsumeIntoMemberVarintTooLong) {
  RepeatedMessageField<InnerStruct> field{1};
  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageField, EmptyWithoutVarint) {
  RepeatedMessageField<InnerStruct> field{1};
  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageField, InvalidVarint) {
  RepeatedMessageField<InnerStruct> field{1};
  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(RepeatedMessageField, SerializeEmpty) {
  RepeatedMessageField<InnerStruct> field{1};
  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

TEST(RepeatedMessageField, SerializeNonEmpty) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct(0x23, 0x7a));
  field.mutable_values()->push_back(InnerStruct());
  field.mutable_values()->back().set_uint32_member_1((0x01));
  std::string buffer = "BUFFERBUFFERBUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(10));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 10));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[10]));
  EXPECT_THAT(buffer.substr(0, 10),
              Eq(absl::StrCat(FieldWithNumber(1).IsSubMessage(
                                  {FieldWithNumber(1).IsVarint(0x23),
                                   FieldWithNumber(2).IsVarint(0x7a)}),
                              FieldWithNumber(1).IsSubMessage(
                                  {FieldWithNumber(1).IsVarint(0x01)}))));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(10), Eq("ERBUFFERBUFFERBUFFERBUFFER"));
}

TEST(RepeatedMessageField, SerializeNonEmptyWithEmptyInnerStruct) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct());
  std::string buffer = "BUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  // Tag (1 << 3 | 2) = 0x0a, Length = 0x00. Total 2 bytes.
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 2));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[2]));
  EXPECT_THAT(buffer.substr(0, 2), Eq(HexDecodeOrDie("0a00")));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(2), Eq("FFER"));
}

TEST(RepeatedMessageField, SerializeTooSmallBuffer) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct(0x23, 0x7a));
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(RepeatedMessageField, SerializeSmallerBuffer) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct(0x23, 0x7a));
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(RepeatedMessageField, SerializeVerySmallBuffer) {
  RepeatedMessageField<InnerStruct> field{1};
  field.mutable_values()->push_back(InnerStruct(0x23, 0x7a));
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

TEST(RepeatedMessageField, Accessors) {
  RepeatedMessageField<InnerStruct> field{1};
  EXPECT_EQ(field.values_size(), 0);

  InnerStruct* v1 = field.add_values();
  v1->set_uint32_member_1(1);
  EXPECT_EQ(field.values_size(), 1);
  EXPECT_EQ(field.values(0).uint32_member_1(), 1);
  EXPECT_EQ(v1, field.mutable_values(0));

  field.mutable_values(0)->set_uint32_member_1(2);
  EXPECT_EQ(field.values(0).uint32_member_1(), 2);

  InnerStruct* v2 = field.add_values();
  v2->set_uint32_member_1(3);
  v2->set_uint32_member_2(4);
  EXPECT_EQ(field.values_size(), 2);
  EXPECT_EQ(field.values(1).uint32_member_1(), 3);
  EXPECT_EQ(field.values(1).uint32_member_2(), 4);

  EXPECT_EQ(field.values().size(), 2);
  EXPECT_EQ(field.mutable_values()->size(), 2);
  field.mutable_values()->back().set_uint32_member_1(5);
  EXPECT_EQ(field.values(1).uint32_member_1(), 5);
  EXPECT_EQ(field.values(1).uint32_member_2(), 4);
}

// -----------------------------------------------------------------------------
// MessageField tests.

class Submessage : public Message {
 public:
  Submessage() = default;

  uint32_t uint32_field() const { return uint32_field_.value(); }
  void set_uint32_field(uint32_t value) { uint32_field_.set_value(value); }
  const std::string& bytes_field() const { return bytes_field_.value(); }
  void set_bytes_field(absl::string_view value) {
    bytes_field_.set_value(value);
  }

  bool operator==(const Submessage& other) const {
    return uint32_field_.value() == other.uint32_field_.value() &&
           bytes_field_.value() == other.bytes_field_.value();
  }

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{{&uint32_field_, &bytes_field_}}[i];
  }

  Uint32Field uint32_field_{1};
  // Arbitrary padding to make sure pasing/serializing doesn't rely on
  // fields being contiguous in memory.
  [[maybe_unused]] uint8_t padding_[20] = {};
  BytesField bytes_field_{2};
};

enum class TestEnum : uint32_t {
  kZero = 0,
  kOne = 1,
  kTwo = 2,
};

bool TestEnum_IsValid(uint32_t value) {
  return value == static_cast<uint32_t>(TestEnum::kZero) ||
         value == static_cast<uint32_t>(TestEnum::kOne) ||
         value == static_cast<uint32_t>(TestEnum::kTwo);
}

class TestMessage : public Message {
 public:
  TestMessage() = default;

  uint32_t uint32_field() const { return uint32_field_.value(); }
  void set_uint32_field(uint32_t value) { uint32_field_.set_value(value); }

  const std::string& bytes_field() const { return bytes_field_.value(); }
  void set_bytes_field(const std::string& value) {
    bytes_field_.set_value(value);
  }

  const Submessage& sub_message_field() const {
    return sub_message_field_.value();
  }
  Submessage* mutable_sub_message_field() {
    return sub_message_field_.mutable_value();
  }

  TestEnum enum_field() const { return enum_field_.value(); }
  void set_enum_field(TestEnum value) { enum_field_.set_value(value); }

  bool operator==(const TestMessage& other) const {
    return uint32_field_.value() == other.uint32_field_.value() &&
           bytes_field_.value() == other.bytes_field_.value() &&
           sub_message_field_.value() == other.sub_message_field_.value() &&
           enum_field_.value() == other.enum_field_.value();
  }

 private:
  size_t num_fields() const override { return 4; }
  const Field* field(int i) const override {
    return std::array<const Field*, 4>{
        {&uint32_field_, &bytes_field_, &sub_message_field_, &enum_field_}}[i];
  }

  Uint32Field uint32_field_{1};
  BytesField bytes_field_{2};
  MessageField<Submessage> sub_message_field_{3};
  EnumField<TestEnum> enum_field_{4, &TestEnum_IsValid, TestEnum::kZero};
};

TEST(MessageFieldTest, CopyConstructor) {
  MessageField<TestMessage> field(1);
  field.mutable_value()->set_uint32_field(123);
  field.mutable_value()->set_bytes_field("test");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(456);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field");
  field.mutable_value()->set_enum_field(TestEnum::kOne);

  MessageField<TestMessage> field2 = field;
  EXPECT_THAT(field2.value(), Eq(field.value()));

  // Make changes to field to verify that field2 is not changed.
  field.mutable_value()->set_uint32_field(1234);
  field.mutable_value()->set_bytes_field("test2");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(4567);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field2");
  field.mutable_value()->set_enum_field(TestEnum::kTwo);
  EXPECT_THAT(field2.value(), Not(Eq(field.value())));
}

TEST(MessageFieldTest, CopyAssignment) {
  MessageField<TestMessage> field(1);
  field.mutable_value()->set_uint32_field(123);
  field.mutable_value()->set_bytes_field("test");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(456);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field");
  field.mutable_value()->set_enum_field(TestEnum::kOne);
  MessageField<TestMessage> field2(2);
  field2.mutable_value()->set_uint32_field(999);

  field2 = field;
  EXPECT_THAT(field2.value(), Eq(field.value()));

  // Make changes to field to verify that field2 is not changed.
  field.mutable_value()->set_uint32_field(1234);
  field.mutable_value()->set_bytes_field("test2");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(4567);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field2");
  field.mutable_value()->set_enum_field(TestEnum::kTwo);
  EXPECT_THAT(field2.value(), Not(Eq(field.value())));
}

TEST(MessageFieldTest, MoveConstructor) {
  MessageField<TestMessage> field(1);
  field.mutable_value()->set_uint32_field(123);
  field.mutable_value()->set_bytes_field("test");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(456);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field");
  field.mutable_value()->set_enum_field(TestEnum::kTwo);
  MessageField<TestMessage> field2 = std::move(field);

  // Verify field2 has the correct values.
  EXPECT_THAT(field2.value().uint32_field(), Eq(123));
  EXPECT_THAT(field2.value().bytes_field(), Eq("test"));
  EXPECT_THAT(field2.value().sub_message_field().uint32_field(), Eq(456));
  EXPECT_THAT(field2.value().sub_message_field().bytes_field(), Eq("field"));
}

TEST(MessageFieldTest, MoveAssignment) {
  MessageField<TestMessage> field(1);
  field.mutable_value()->set_uint32_field(123);
  field.mutable_value()->set_bytes_field("test");
  field.mutable_value()->mutable_sub_message_field()->set_uint32_field(456);
  field.mutable_value()->mutable_sub_message_field()->set_bytes_field("field");
  field.mutable_value()->set_enum_field(TestEnum::kTwo);
  MessageField<TestMessage> field2(2);
  field2.mutable_value()->set_uint32_field(999);
  field2 = std::move(field);

  // Verify field2 has the correct values.
  EXPECT_THAT(field2.value().uint32_field(), Eq(123));
  EXPECT_THAT(field2.value().bytes_field(), Eq("test"));
  EXPECT_THAT(field2.value().sub_message_field().uint32_field(), Eq(456));
  EXPECT_THAT(field2.value().sub_message_field().bytes_field(), Eq("field"));
}

TEST(MessageFieldTest, ClearMemberWorks) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(123, 456);
  field.Clear();
  EXPECT_THAT(field.has_value(), IsFalse());
}

TEST(MessageFieldTest, ConsumeIntoMemberSuccessCases) {
  MessageField<InnerStruct> field{1};

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageFieldTest, ConsumeIntoMemberWithCrcSuccessCases) {
  MessageField<InnerStruct> field{1};

  std::string bytes =
      absl::StrCat(/* 4 bytes */ HexDecodeOrDie("04"),
                   /* Int field, tag 1, value 0x23 */ HexDecodeOrDie("0823"),
                   /* Int field, tag 2, value 0x7a */ HexDecodeOrDie("107a"),
                   "remaining_data");
  absl::crc32c_t crc{};
  ParsingState parsing_state = ParsingState(bytes, &crc);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  EXPECT_THAT(parsing_state.RemainingData(), Eq("remaining_data"));
  EXPECT_THAT(crc, Eq(absl::ComputeCrc32c(bytes.substr(0, 5))));
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0x23));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageFieldTest, ConsumeIntoMemberEmptyStringNullopt) {
  MessageField<InnerStruct> field{1};

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0));
}

TEST(MessageFieldTest, ConsumeIntoMemberEmptyString) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(10, 0);

  std::string bytes = HexDecodeOrDie("00");
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear the fields because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(10));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0));
}

TEST(MessageFieldTest, ConsumeIntoMemberDoesNotClear) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(10, 0);

  std::string bytes = absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                                   /* Int field, tag 2, value 0x7a */
                                   HexDecodeOrDie("107a"));
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(10));
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageFieldTest, ConsumeIntoMemberWithInnerStructNullopt) {
  MessageField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(/* 4 bytes */ HexDecodeOrDie("02"),
                                   /* Int field, tag 2, value 0x7a */
                                   HexDecodeOrDie("107a"));
  ParsingState parsing_state = ParsingState(bytes);
  // This does not clear uint32_member_1 because if there are multiple blocks
  // for the same field we merge them.
  ASSERT_THAT(field.ConsumeIntoMember(parsing_state), IsTrue());
  ASSERT_THAT(field.has_value(), IsTrue());
  EXPECT_THAT(field.value().uint32_member_1(), Eq(0));  // Default value.
  EXPECT_THAT(field.value().uint32_member_2(), Eq(0x7a));
}

TEST(MessageFieldTest, ConsumeIntoMemberVarintTooLong) {
  MessageField<InnerStruct> field{1};

  std::string bytes = /* LengthDelimetedLength: */ HexDecodeOrDie("01");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(MessageFieldTest, EmptyWithoutVarint) {
  MessageField<InnerStruct> field{1};

  std::string bytes = "";
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

TEST(MessageFieldTest, InvalidVarint) {
  MessageField<InnerStruct> field{1};

  std::string bytes = absl::StrCat(HexDecodeOrDie("808080808000"), "abcde");
  ParsingState parsing_state = ParsingState(bytes);
  EXPECT_THAT(field.ConsumeIntoMember(parsing_state), IsFalse());
}

// When the optional struct is not set, we produce an empty serialization.
TEST(MessageFieldTest, SerializeNulloptProducesEmptySerialization) {
  MessageField<InnerStruct> field{1};

  std::string buffer = "abc";
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(0));
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(3));
  EXPECT_THAT(buffer, Eq("abc"));
}

// When the optional struct is set to the default value, we produce a
// serialization of the empty submessage.
TEST(MessageFieldTest,
     SerializeInnerStructWithDefaultValuesProducesEmptySubmessage) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct{};

  std::string buffer = "abc";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(2));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(1));
  // Serialized as empty submessage.
  EXPECT_THAT(buffer.substr(0, 2), Eq(FieldWithNumber(1).IsSubMessage({})));
}

TEST(MessageFieldTest, SerializeNonEmpty) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(0x23, 0x7a);
  std::string buffer = "BUFFERBUFFERBUFFERBUFFER";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.GetSerializedSizeIncludingTag(), Eq(6));
  EXPECT_THAT(field.SerializeWithTagInto(state), IsOk());
  EXPECT_THAT(state.GetBuffer().size(), Eq(buffer.size() - 6));
  EXPECT_THAT(&(state.GetBuffer())[0], Eq(&buffer[6]));
  EXPECT_THAT(
      buffer.substr(0, 6),
      Eq(FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsVarint(0x23),
                                          FieldWithNumber(2).IsVarint(0x7a)})));
  // Rest is untouched
  EXPECT_THAT(buffer.substr(6), Eq("BUFFERBUFFERBUFFER"));
}

TEST(MessageFieldTest, SerializeTooSmallBuffer) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(0x23, 0x7a);
  std::string buffer = "BUFFE";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer can hold the tag, but not the varint of the length.
TEST(MessageFieldTest, SerializeSmallerBuffer) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(0x23, 0x7a);
  std::string buffer = "B";
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

// The buffer won't even hold the varint.
TEST(MessageFieldTest, SerializeVerySmallBuffer) {
  MessageField<InnerStruct> field{1};
  *field.mutable_value() = InnerStruct(0x23, 0x7a);
  std::string buffer;
  SerializationState state = SerializationState(absl::MakeSpan(buffer));
  EXPECT_THAT(field.SerializeWithTagInto(state), Not(IsOk()));
}

class MessageWithBrokenFieldOrder : public Message {
 public:
  MessageWithBrokenFieldOrder() = default;

  using Message::ParseFromString;

 private:
  size_t num_fields() const override { return 2; }
  const Field* field(int i) const override {
    return std::array<const Field*, 2>{
        {&uint32_member_2_, &uint32_member_1_}}[i];
  }

  Uint32Field uint32_member_1_{1};
  Uint32Field uint32_member_2_{2};
};

TEST(MessageFieldDeathTest, DiesOnParse) {
  MessageWithBrokenFieldOrder message;
  EXPECT_DEBUG_DEATH(
      { message.ParseFromString(HexDecodeOrDie("0800")); },
      HasSubstr("Fields returned by field() must be sorted"));
}

}  // namespace
}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
