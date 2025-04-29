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

#include "tink/internal/proto_parser.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/proto_parser_options.h"
#include "tink/internal/proto_test_proto.pb.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretValue;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::Test;

constexpr int32_t kUint32Field1Tag = 1;
constexpr int32_t kUint32Field2Tag = 2;
constexpr int32_t kBytesField1Tag = 3;
constexpr int32_t kBytesField2Tag = 4;
constexpr int32_t kInnerMessageField = 10;
constexpr int32_t kInnerMessageField2 = 11;
constexpr int32_t kEnumField = 111;
constexpr int32_t kUint32FieldWithLargeTag = 536870911;

enum class MyEnum : uint32_t {
  kZero = 0,
  kOne = 1,
};

struct InnerStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
  SecretData secret_data_member_1;
  SecretData secret_data_member_2;
  std::vector<SecretData> repeated_secret_data_member1;
  std::vector<SecretData> repeated_secret_data_member2;
};

struct ParsedStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
  uint64_t uint64_member_1;
  absl::optional<uint32_t> optional_uint32_member_1;
  std::string string_member_1;
  std::string string_member_2;
  SecretData secret_data_member_1;
  SecretData secret_data_member_2;
  InnerStruct inner_member_1;
  InnerStruct inner_member_2;
  absl::optional<InnerStruct> optional_inner_member_1;
  absl::optional<InnerStruct> optional_inner_member_2;
  MyEnum enum_member;
};

// PARSE TESTS =================================================================
TEST(ProtoParserTest, Uint32AbsentWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse("");
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(0));
}

TEST(ProtoParserTest, Uint32DefaultValueWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse(HexDecodeOrDie("0800"));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(0));
}

TEST(ProtoParserTest, SingleUint32Works) {
  ProtoTestProto proto;
  proto.set_uint32_field1(123);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(123));
}

TEST(ProtoParserTest, OptionalUint32AbsentWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse("");
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->optional_uint32_member_1, Eq(absl::nullopt));
}

TEST(ProtoParserTest, OptionalUint32DefaultWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse(HexDecodeOrDie("0800"));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->optional_uint32_member_1, Optional(0));
}

TEST(ProtoParserTest, OptionalUint32NonZeroWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse(HexDecodeOrDie("0801"));
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->optional_uint32_member_1, Optional(1));
}

TEST(ProtoParserTest, SingleUint64Works) {
  ProtoTestProto proto;
  proto.set_uint64_field1(0xffffffffff);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint64Field(5, &ParsedStruct::uint64_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint64_member_1, Eq(0xffffffffff));
}

TEST(ProtoParserTest, SingleEnumWorks) {
  ProtoTestProto proto;
  proto.set_uint32_field1(1);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddEnumField(kUint32Field1Tag, &ParsedStruct::enum_member,
                        [](uint32_t) { return true; })
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->enum_member, Eq(MyEnum::kOne));
}

TEST(ProtoParserTest, EnumDefaultNotSerialized) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddEnumField(kUint32Field1Tag, &ParsedStruct::enum_member,
                        [](uint32_t) { return true; })
          .BuildOrDie();
  ParsedStruct s;
  s.enum_member = MyEnum::kZero;
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, EnumAlwaysSerializeWorks) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddEnumField(
              kUint32Field1Tag, &ParsedStruct::enum_member,
              [](uint32_t) { return true; },
              ProtoFieldOptions::kAlwaysSerialize)
          .BuildOrDie();
  ParsedStruct s;
  s.enum_member = MyEnum::kZero;
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  // 08 = "kVarint Field, Field number 1"
  ASSERT_THAT(HexEncode(*serialized), Eq("0800"));
}

TEST(ProtoParserTest, SingleBytesFieldStringWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field1("some bytes field");

  std::string value;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->string_member_1, Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field1("some bytes field");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(SecretDataAsStringView(parsed->secret_data_member_1),
              Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldStringLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialized_proto).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("exceeds remaining input")));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataTooLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  StatusIs(absl::StatusCode::kInvalidArgument,
           HasSubstr("exceeds remaining input"));
}

TEST(ProtoParserTest, MultipleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field1("some bytes field");
  proto.set_bytes_field2("another bytes field");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_2)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(SecretDataAsStringView(parsed->secret_data_member_1),
              Eq("some bytes field"));
  EXPECT_THAT(SecretDataAsStringView(parsed->secret_data_member_2),
              Eq("another bytes field"));
}

TEST(ProtoParserTest, MultipleUint32Work) {
  ProtoTestProto proto;
  proto.set_uint32_field1(0xfe84becc);
  proto.set_uint32_field2(445533);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(0xfe84becc));
  EXPECT_THAT(parsed->uint32_member_2, Eq(445533));
}

TEST(ProtoParserTest, MultipleUint32OrderIsIgnored) {
  ProtoTestProto proto1;
  proto1.set_uint32_field1(1);

  ProtoTestProto proto2;
  proto2.set_uint32_field2(2);

  std::string serialized =
      absl::StrCat(proto2.SerializeAsString(), proto1.SerializeAsString());
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse(serialized);
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(1));
  EXPECT_THAT(parsed->uint32_member_2, Eq(2));
}

TEST(ProtoParserTest, ParseMessageField) {
  ProtoTestProto proto;
  proto.mutable_inner_proto_field1()->set_inner_proto_uint32_field3(123);

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());

  absl::StatusOr<ParsedStruct> outer_parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(outer_parsed, IsOk());
  EXPECT_THAT(outer_parsed->inner_member_1.uint32_member_1, Eq(123));
}

TEST(ProtoParserTest, ParseMessageFieldWithPresence) {
  ProtoTestProto proto;
  proto.mutable_inner_proto_field1()->set_inner_proto_uint32_field3(123);

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser1 =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser1.status(), IsOk());
  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser2 =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser2.status(), IsOk());
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageFieldWithPresence<InnerStruct>(
              kInnerMessageField, &ParsedStruct::optional_inner_member_1,
              *std::move(inner_parser1))
          .AddMessageFieldWithPresence<InnerStruct>(
              kInnerMessageField2, &ParsedStruct::optional_inner_member_2,
              *std::move(inner_parser2))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());

  absl::StatusOr<ParsedStruct> outer_parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(outer_parsed, IsOk());
  ASSERT_THAT(outer_parsed->optional_inner_member_1.has_value(), IsTrue());
  ASSERT_THAT(outer_parsed->optional_inner_member_2.has_value(), IsFalse());
  EXPECT_THAT(outer_parsed->optional_inner_member_1->uint32_member_1, Eq(123));
}

TEST(ProtoParserTest, ParseDoubleMessageField) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField<InnerStruct>(
              1, &ParsedStruct::inner_member_1,
              ProtoParserBuilder<InnerStruct>()
                  .AddUint32Field(10, &InnerStruct::uint32_member_1)
                  .BuildOrDie())
          .AddMessageField<InnerStruct>(
              2, &ParsedStruct::inner_member_2,
              ProtoParserBuilder<InnerStruct>()
                  .AddUint32Field(10, &InnerStruct::uint32_member_1)
                  .BuildOrDie())
          .BuildOrDie();
  std::string serialization = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(10).IsVarint(100)}),
      FieldWithNumber(2).IsSubMessage({FieldWithNumber(10).IsVarint(20)}));

  absl::StatusOr<ParsedStruct> outer_parsed = parser.Parse(serialization);
  ASSERT_THAT(outer_parsed, IsOk());
  EXPECT_THAT(outer_parsed->inner_member_1.uint32_member_1, Eq(100));
  EXPECT_THAT(outer_parsed->inner_member_2.uint32_member_1, Eq(20));
}

TEST(ProtoParserTest, ParseDoubleMessageFieldWithPresence) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageFieldWithPresence<InnerStruct>(
              1, &ParsedStruct::optional_inner_member_1,
              ProtoParserBuilder<InnerStruct>()
                  .AddUint32Field(10, &InnerStruct::uint32_member_1)
                  .BuildOrDie())
          .AddMessageFieldWithPresence<InnerStruct>(
              2, &ParsedStruct::optional_inner_member_2,
              ProtoParserBuilder<InnerStruct>()
                  .AddUint32Field(10, &InnerStruct::uint32_member_1)
                  .BuildOrDie())
          .BuildOrDie();
  std::string serialization = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(10).IsVarint(100)}),
      FieldWithNumber(2).IsSubMessage({FieldWithNumber(10).IsVarint(20)}));

  absl::StatusOr<ParsedStruct> outer_parsed = parser.Parse(serialization);
  ASSERT_THAT(outer_parsed, IsOk());
  ASSERT_THAT(outer_parsed->optional_inner_member_1.has_value(), IsTrue());
  ASSERT_THAT(outer_parsed->optional_inner_member_2.has_value(), IsTrue());
  EXPECT_THAT(outer_parsed->optional_inner_member_1->uint32_member_1, Eq(100));
  EXPECT_THAT(outer_parsed->optional_inner_member_2->uint32_member_1, Eq(20));
}

TEST(ProtoParserTest, EmptyMessageAlwaysWorks) {
  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_1)
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse("");
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(0));
  EXPECT_THAT(parsed->uint32_member_2, Eq(0));
  EXPECT_THAT(parsed->string_member_1, IsEmpty());
  EXPECT_THAT(parsed->secret_data_member_1, IsEmpty());
}

TEST(ProtoParserTest, FailsIfFieldIsRepeated) {
  EXPECT_THAT(
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_2)
          .Build(),
      Not(IsOk()));
}

TEST(ProtoParserTest, VarintUint32Parsing) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  ProtoTestProto proto;
  for (uint32_t v :
       std::vector<uint32_t>({0, 0x01, 0x7f, 0xff, 0x3a22, 0xb084bbbe,
                              0x7fffffff, 0x80000000, 0xffffffff})) {
    SCOPED_TRACE(v);
    proto.set_uint32_field1(v);
    absl::StatusOr<ParsedStruct> parsed =
        parser->Parse(proto.SerializeAsString());
    ASSERT_THAT(parsed, IsOk());
    EXPECT_THAT(parsed->uint32_member_1, Eq(v));
  }
}

TEST(ProtoParserTest, MaxTagNumber) {
  ProtoTestProto proto;
  proto.set_uint32_field_with_large_tag(777);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32FieldWithLargeTag,
                          &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed =
      parser->Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(777));
}

TEST(ProtoParserTest, FailsOnEmptyVarint) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t.
  std::string serialization = test::HexDecodeOrDie("08");
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialization).status(), Not(IsOk()));
}

TEST(ProtoParserTest, FailsOn11ByteVarint) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This fails already in varint 64 parsing because it is too
  // long.)
  std::string serialization = test::HexDecodeOrDie("08ffffffffffffffffffffff");
  ASSERT_THAT(serialization.size(), Eq(1 + 11));
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialization).status(), Not(IsOk()));
}

TEST(ProtoParserTest, SucceedsOn5ByteVarintUint32) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. We provide a varint which is larger than 2^32.
  std::string serialization = test::HexDecodeOrDie("08ffffffff7f");
  ASSERT_THAT(serialization.size(), Eq(1 + 5));
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<ParsedStruct> parsed = parser->Parse(serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(4294967295));
}

TEST(ProtoParserTest, SubfieldsAreNotClearedOnDoubleMessages) {
  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(20, &InnerStruct::uint32_member_1)
          .AddUint32Field(21, &InnerStruct::uint32_member_2)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());

  ProtoTestProto proto1;
  proto1.mutable_inner_proto_field1()->set_inner_proto_uint32_field1(77);
  proto1.mutable_inner_proto_field1()->set_inner_proto_uint32_field2(66);

  ProtoTestProto proto2;
  proto2.mutable_inner_proto_field1()->set_inner_proto_uint32_field2(55);

  std::string serialized =
      absl::StrCat(proto1.SerializeAsString(), proto2.SerializeAsString());

  ProtoTestProto parsed_proto;
  ASSERT_THAT(parsed_proto.ParseFromString(serialized), IsTrue());
  // The 77 from the first instance stays
  EXPECT_THAT(parsed_proto.inner_proto_field1().inner_proto_uint32_field1(),
              Eq(77));
  // The 55 is overwritten
  EXPECT_THAT(parsed_proto.inner_proto_field1().inner_proto_uint32_field2(),
              Eq(55));

  absl::StatusOr<ParsedStruct> parsed = parser->Parse(serialized);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->inner_member_1.uint32_member_1, Eq(77));
  EXPECT_THAT(parsed->inner_member_1.uint32_member_2, Eq(55));
}

TEST(ProtoParserTest, SubfieldsAreNotClearedOnDoubleMessagesWithPresence) {
  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(20, &InnerStruct::uint32_member_1)
          .AddUint32Field(21, &InnerStruct::uint32_member_2)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageFieldWithPresence<InnerStruct>(
              kInnerMessageField, &ParsedStruct::optional_inner_member_1,
              *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());

  ProtoTestProto proto1;
  proto1.mutable_inner_proto_field1()->set_inner_proto_uint32_field1(77);
  proto1.mutable_inner_proto_field1()->set_inner_proto_uint32_field2(66);

  ProtoTestProto proto2;
  proto2.mutable_inner_proto_field1()->set_inner_proto_uint32_field2(55);

  std::string serialized =
      absl::StrCat(proto1.SerializeAsString(), proto2.SerializeAsString());

  ProtoTestProto parsed_proto;
  ASSERT_THAT(parsed_proto.ParseFromString(serialized), IsTrue());
  // The 77 from the first instance stays
  EXPECT_THAT(parsed_proto.inner_proto_field1().inner_proto_uint32_field1(),
              Eq(77));
  // The 55 is overwritten
  EXPECT_THAT(parsed_proto.inner_proto_field1().inner_proto_uint32_field2(),
              Eq(55));

  absl::StatusOr<ParsedStruct> parsed = parser->Parse(serialized);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->optional_inner_member_1->uint32_member_1, Eq(77));
  EXPECT_THAT(parsed->optional_inner_member_1->uint32_member_2, Eq(55));
}

TEST(ProtoParserTest, SkipUnknownFields) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .BuildOrDie();

  ProtoTestProto proto1;
  proto1.set_uint32_field1(123);
  // Unknown field
  ProtoTestProto proto2;
  proto2.set_uint32_field2(555);

  ProtoTestProto proto3;
  proto3.set_bytes_field1("foo");

  std::string serialized =
      absl::StrCat(proto1.SerializeAsString(), proto2.SerializeAsString(),
                   proto3.SerializeAsString());

  absl::StatusOr<ParsedStruct> parsed = parser.Parse(serialized);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(123));
  EXPECT_THAT(parsed->string_member_1, Eq("foo"));
}

#if not TINK_CPP_SECRET_DATA_IS_STD_VECTOR
TEST(ProtoParserTest, SingleBytesFieldSecretDataParsingWorks) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  std::string serialization =
      absl::StrCat(FieldWithNumber(1).IsString("some text"),
                   FieldWithNumber(2).IsVarint(101));

  absl::StatusOr<std::pair<ParsedStruct, SecretValue<absl::crc32c_t>>> parsed =
      parser->ParseWithCrc(serialization);
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->first.secret_data_member_1.AsStringView(),
              Eq("some text"));
  EXPECT_THAT(parsed->first.secret_data_member_1.GetCrc32c(),
              Eq(absl::ComputeCrc32c("some text")));
  EXPECT_THAT(parsed->first.uint32_member_1, Eq(101));
  EXPECT_THAT(parsed->second.value(), Eq(absl::ComputeCrc32c(serialization)));
}

TEST(ProtoParserTest, MultipleBytesFieldSecretDataParsingWorks) {
  std::string text11 = "Text for first submessage, first field";
  std::string text12 = "Text for first submessage, second field";
  std::string text21 = "Text for second submessage, first field";
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField(1, &ParsedStruct::inner_member_1,
                           ProtoParserBuilder<InnerStruct>()
                               .AddBytesSecretDataField(
                                   1, &InnerStruct::secret_data_member_1)
                               .AddBytesSecretDataField(
                                   2, &InnerStruct::secret_data_member_2)
                               .BuildOrDie())
          .AddMessageField(2, &ParsedStruct::inner_member_2,
                           ProtoParserBuilder<InnerStruct>()
                               .AddBytesSecretDataField(
                                   1, &InnerStruct::secret_data_member_1)
                               .AddBytesSecretDataField(
                                   2, &InnerStruct::secret_data_member_2)
                               .BuildOrDie())
          .BuildOrDie();
  std::string serialization = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsString(text11),
                                       FieldWithNumber(2).IsString(text12)}),
      FieldWithNumber(2).IsSubMessage({FieldWithNumber(1).IsString(text21)}));
  absl::StatusOr<std::pair<ParsedStruct, SecretValue<absl::crc32c_t>>> parsed =
      parser.ParseWithCrc(serialization);
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(
      parsed->first.inner_member_1.secret_data_member_1.ValidateCrc32c(),
      IsOk());
  EXPECT_THAT(parsed->first.inner_member_1.secret_data_member_1.AsStringView(),
              Eq(text11));
  EXPECT_THAT(
      parsed->first.inner_member_1.secret_data_member_2.ValidateCrc32c(),
      IsOk());
  EXPECT_THAT(parsed->first.inner_member_1.secret_data_member_2.AsStringView(),
              Eq(text12));
  EXPECT_THAT(
      parsed->first.inner_member_2.secret_data_member_1.ValidateCrc32c(),
      IsOk());
  EXPECT_THAT(parsed->first.inner_member_2.secret_data_member_1.AsStringView(),
              Eq(text21));
}
#endif  // not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

TEST(ProtoParserTest, RepatedSecretDataWorks) {
  std::string text110 = "this is for field 1, subfield 1, the first string";
  std::string text111 = "this is for field 1, subfield 1, the second string";
  std::string text112 = "this is for field 1, subfield 1, the third string";
  std::string text120 = "this is for field 1, subfield 2, the only string";
  std::string text210 = "this is for field 2, subfield 1.";

  std::string serialization = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsString(text110),
                                       FieldWithNumber(1).IsString(text111),
                                       FieldWithNumber(2).IsString(text120)}),
      FieldWithNumber(2).IsSubMessage({FieldWithNumber(1).IsString(text210)}),
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsString(text112)}));
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField(
              1, &ParsedStruct::inner_member_1,
              ProtoParserBuilder<InnerStruct>()
                  .AddRepeatedBytesSecretDataField(
                      1, &InnerStruct::repeated_secret_data_member1)
                  .AddRepeatedBytesSecretDataField(
                      2, &InnerStruct::repeated_secret_data_member2)
                  .BuildOrDie())
          .AddMessageField(
              2, &ParsedStruct::inner_member_2,
              ProtoParserBuilder<InnerStruct>()
                  .AddRepeatedBytesSecretDataField(
                      1, &InnerStruct::repeated_secret_data_member1)
                  .AddRepeatedBytesSecretDataField(
                      2, &InnerStruct::repeated_secret_data_member2)
                  .BuildOrDie())
          .BuildOrDie();
  absl::StatusOr<ParsedStruct> parsed_struct = parser.Parse(serialization);
  ASSERT_THAT(parsed_struct, IsOk());
  EXPECT_THAT(parsed_struct->inner_member_1.repeated_secret_data_member1,
              SizeIs(3));
  EXPECT_THAT(parsed_struct->inner_member_1.repeated_secret_data_member2,
              SizeIs(1));
  EXPECT_THAT(parsed_struct->inner_member_2.repeated_secret_data_member1,
              SizeIs(1));
  EXPECT_THAT(parsed_struct->inner_member_2.repeated_secret_data_member2,
              SizeIs(0));
  EXPECT_THAT(
      SecretDataAsStringView(
          parsed_struct->inner_member_1.repeated_secret_data_member1[0]),
      Eq(text110));
  EXPECT_THAT(
      SecretDataAsStringView(
          parsed_struct->inner_member_1.repeated_secret_data_member1[1]),
      Eq(text111));
  EXPECT_THAT(
      SecretDataAsStringView(
          parsed_struct->inner_member_1.repeated_secret_data_member1[2]),
      Eq(text112));
  EXPECT_THAT(
      SecretDataAsStringView(
          parsed_struct->inner_member_1.repeated_secret_data_member2[0]),
      Eq(text120));
  EXPECT_THAT(
      SecretDataAsStringView(
          parsed_struct->inner_member_2.repeated_secret_data_member1[0]),
      Eq(text210));
}

// Found by a prototype fuzzer.
TEST(ProtoParserTest, Regression1) {
  std::string serialization = HexDecodeOrDie("a20080808080808080808000");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(4, &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialization).status(), Not(IsOk()));
}

// Found by the fuzzer -- (Wiretype,Tag) with overflown tag.
TEST(ProtoParserTest, Regression2) {
  std::string serialization = HexDecodeOrDie("9080808080efeed90752");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(4, &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialization).status(), Not(IsOk()));
}

// SERIALIZATION TESTS =========================================================
TEST(ProtoParserTest, SerializeUint32Field) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("087a")));
}

TEST(ProtoParserTest, Uint32DefaultNotSerialized) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ParsedStruct s;
  s.uint32_member_1 = 0;
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, Uint32AlwaysSerializeWorks) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1,
                          ProtoFieldOptions::kAlwaysSerialize)
          .BuildOrDie();
  ParsedStruct s;
  s.uint32_member_1 = 0;
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  // 08 = "kVarint Field, Field number 1"
  ASSERT_THAT(HexEncode(*serialized), Eq("0800"));
}

TEST(ProtoParserTest, SerializeOptionalFieldAbsent) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  ParsedStruct s;
  s.optional_uint32_member_1 = absl::nullopt;
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("")));
}

TEST(ProtoParserTest, SerializeOptionalFieldPresent) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  ParsedStruct s;
  s.optional_uint32_member_1 = 1;
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("0801")));
}

TEST(ProtoParserTest, SerializeOptionalFieldPresentDefault) {
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddOptionalUint32Field(1, &ParsedStruct::optional_uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  ParsedStruct s;
  s.optional_uint32_member_1 = 0;
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("0800")));
}

TEST(ProtoParserTest, SerializeEnumField) {
  ParsedStruct s;
  s.enum_member = MyEnum::kOne;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddEnumField<MyEnum>(1, &ParsedStruct::enum_member,
                                [](uint32_t) { return true; })
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("0801")));
}

TEST(ProtoParserTest, SerializeIntoSecretData) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<SecretData> serialized = parser->SerializeIntoSecretData(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*serialized), Eq(HexDecodeOrDie("087a")));
}
TEST(ProtoParserTest, SerializeTagVariations) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  for (const std::pair<std::string, uint32_t> pair :
       std::vector<std::pair<std::string, uint32_t>>{
           {"087a", 1},
           {"107a", 2},
           {"787a", 15},
           {"80017a", 16},
           {"f8ffffff0f7a", 536870911}}) {
    SCOPED_TRACE(pair.first);
    absl::StatusOr<ProtoParser<ParsedStruct>> parser =
        ProtoParserBuilder<ParsedStruct>()
            .AddUint32Field(pair.second, &ParsedStruct::uint32_member_1)
            .Build();
    ASSERT_THAT(parser.status(), IsOk());
    absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
    ASSERT_THAT(serialized, IsOk());
    EXPECT_THAT(HexEncode(*serialized), Eq(pair.first));
  }
}

TEST(ProtoParserTest, SerializeUint32Variations) {
  ParsedStruct s;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());

  for (const std::pair<std::string, uint32_t> pair :
       std::vector<std::pair<std::string, uint32_t>>{
           {"", 0x00},
           {"0801", 0x01},
           {"087f", 0x7f},
           {"08ff01", 0xff},
           {"08a274", 0x3a22},
           {"08bef792840b", 0xb084bbbe},
           {"08ffffffff07", 0x7fffffff},
           {"088080808008", 0x80000000},
           {"08ffffffff0f", 0xffffffff},
       }) {
    SCOPED_TRACE(pair.first);
    s.uint32_member_1 = pair.second;
    absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
    ASSERT_THAT(serialized, IsOk());
    EXPECT_THAT(HexEncode(*serialized), Eq(pair.first));
  }
}

TEST(ProtoParserTest, TwoUintFields) {
  ParsedStruct s;
  s.uint32_member_1 = 0x10;
  s.uint32_member_2 = 0xaa;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized), Eq("081010aa01"));
}

TEST(ProtoParserTest, SerializeStringField) {
  ParsedStruct s;
  s.string_member_1 = "This is some string data of arbitrary length";
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(1, &ParsedStruct::string_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a2c", HexEncode(s.string_member_1))));
}

TEST(ProtoParserTest, SerializeStringFieldDefaultNotSerialized) {
  ParsedStruct s;
  s.string_member_1 = "";
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(1, &ParsedStruct::string_member_1)
          .BuildOrDie();
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, SerializeStringFieldAlwaysSerializeWorks) {
  ParsedStruct s;
  s.string_member_1 = "";
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(1, &ParsedStruct::string_member_1,
                               ProtoFieldOptions::kAlwaysSerialize)
          .BuildOrDie();
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(HexEncode(*serialized), Eq("0a00"));
}

TEST(ProtoParserTest, SerializeSecretDataField) {
  ParsedStruct s;
  std::string data = "This is some string data of arbitrary length";
  s.secret_data_member_1 = util::SecretDataFromStringView(data);
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a2c", HexEncode(data))));
}

TEST(ProtoParserTest, SerializeSecretDataFieldDefaultNotSerialized) {
  ParsedStruct s;
  s.secret_data_member_1.clear();
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1)
          .BuildOrDie();
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, SerializeSecredDataFieldAlwaysSerializeWorks) {
  ParsedStruct s;
  s.secret_data_member_1.clear();
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1,
                                   ProtoFieldOptions::kAlwaysSerialize)
          .BuildOrDie();
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized.status(), IsOk());
  ASSERT_THAT(HexEncode(*serialized), Eq("0a00"));
}

#if not TINK_CPP_SECRET_DATA_IS_STD_VECTOR
TEST(ProtoParserTest, SingleBytesFieldSecretDataSerializingWorks) {
  ParsedStruct parsed_struct;
  parsed_struct.secret_data_member_1 = SecretData("some text");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<SecretData> serialized =
      parser->SerializeIntoSecretData(parsed_struct);
  ASSERT_THAT(serialized, IsOk());

  std::string expected_serialization =
      FieldWithNumber(kBytesField1Tag).IsString("some text");
  EXPECT_THAT(serialized->AsStringView(), Eq(expected_serialization));
}

TEST(ProtoParserTest, TwoBytesFieldSecretDataSerializingWorks) {
  ParsedStruct parsed_struct;
  parsed_struct.secret_data_member_1 = SecretData("some text");
  parsed_struct.secret_data_member_2 = SecretData("another text");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_2)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<SecretData> serialized =
      parser->SerializeIntoSecretData(parsed_struct);
  ASSERT_THAT(serialized, IsOk());

  std::string expected_serialization =
      absl::StrCat(FieldWithNumber(kBytesField1Tag).IsString("some text"),
                   FieldWithNumber(kBytesField2Tag).IsString("another text"));
  EXPECT_THAT(serialized->ValidateCrc32c(), IsOk());
  EXPECT_THAT(serialized->AsStringView(), Eq(expected_serialization));
}

// Tests that in order to compute the overall CRC, the CRC field is used (and
// not the data).
TEST(ProtoParserTest, SingleBytesFieldSecretDataWrongCRC) {
  ParsedStruct parsed_struct;
  std::string text1 = "some text of arbitrary length";
  std::string text2 = "different text of same length";
  parsed_struct.secret_data_member_1 =
      SecretData(text1, absl::ComputeCrc32c(text2));

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<SecretData> serialized =
      parser->SerializeIntoSecretData(parsed_struct);
  ASSERT_THAT(serialized, IsOk());

  std::string expected_serialization =
      FieldWithNumber(kBytesField1Tag).IsString(text1);
  std::string serialization_of_computed_crc =
      FieldWithNumber(kBytesField1Tag).IsString(text2);
  EXPECT_THAT(serialized->AsStringView(), Eq(expected_serialization));
  EXPECT_THAT(serialized->GetCrc32c(),
              Eq(absl::ComputeCrc32c(serialization_of_computed_crc)));
}

// Checks that the CRC computation is correct when serializing inner fields.
TEST(ProtoParserTest, CrcOfInnerFieldSerializationWorks) {
  ParsedStruct parsed_struct;
  std::string text1 = "something";
  std::string text2 = "anything, does not matter";
  parsed_struct.inner_member_1.secret_data_member_1 =
      util::SecretDataFromStringView(text1);
  parsed_struct.inner_member_2.secret_data_member_1 =
      util::SecretDataFromStringView(text2);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField(1, &ParsedStruct::inner_member_1,
                           ProtoParserBuilder<InnerStruct>()
                               .AddBytesSecretDataField(
                                   1, &InnerStruct::secret_data_member_1)
                               .BuildOrDie())
          .AddMessageField(2, &ParsedStruct::inner_member_2,
                           ProtoParserBuilder<InnerStruct>()
                               .AddBytesSecretDataField(
                                   1, &InnerStruct::secret_data_member_1)
                               .BuildOrDie())
          .BuildOrDie();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<SecretData> serialized =
      parser->SerializeIntoSecretData(parsed_struct);
  ASSERT_THAT(serialized, IsOk());

  std::string expected_serialization = absl::StrCat(
      FieldWithNumber(1).IsSubMessage({FieldWithNumber(1).IsString(text1)}),
      FieldWithNumber(2).IsSubMessage({FieldWithNumber(1).IsString(text2)}));
  EXPECT_THAT(serialized->AsStringView(), Eq(expected_serialization));
}
#endif  // not TINK_CPP_SECRET_DATA_IS_STD_VECTOR

TEST(ProtoParserTest, SerializeMessageField) {
  ParsedStruct s;
  // Varint encoding: bef792840b
  s.inner_member_1.uint32_member_1 = 2961488830;

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat(/* length delimited field with tag 10*/ "52",
                              /* length 8 */ "08",
                              /* varint field with tag 123456 */ "80a43c",
                              /* uint32_member_1 (varint)*/ "bef792840b")));
}

TEST(ProtoParserTest, SerializeMessageFieldWithPresence) {
  ParsedStruct s;
  // Varint encoding: bef792840b
  s.optional_inner_member_1 = {2961488830, 0};

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageFieldWithPresence<InnerStruct>(
              kInnerMessageField, &ParsedStruct::optional_inner_member_1,
              *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat(/* length delimited field with tag 10*/ "52",
                              /* length 8 */ "08",
                              /* varint field with tag 123456 */ "80a43c",
                              /* uint32_member_1 (varint)*/ "bef792840b")));
}

TEST(ProtoParserTest, SerializeEmpty) {
  ParsedStruct s;
  s.uint32_member_1 = 0;
  s.string_member_1 = "";
  s.secret_data_member_1 = util::SecretDataFromStringView("");
  s.inner_member_1.uint32_member_1 = 0;
  s.enum_member = MyEnum::kZero;

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddBytesStringField(2, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(3, &ParsedStruct::secret_data_member_1)
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .AddEnumField<MyEnum>(kEnumField, &ParsedStruct::enum_member,
                                [](uint32_t) { return true; })
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, SerializeRepatedSecretDataWorks) {
  std::string text110 = "this is for field 1, subfield 1, the first string";
  std::string text111 = "this is for field 1, subfield 1, the second string";
  std::string text112 = "this is for field 1, subfield 1, the third string";
  std::string text120 = "this is for field 1, subfield 2, the only string";
  std::string text210 = "this is for field 2, subfield 1.";

  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddMessageField(
              1, &ParsedStruct::inner_member_1,
              ProtoParserBuilder<InnerStruct>()
                  .AddRepeatedBytesSecretDataField(
                      1, &InnerStruct::repeated_secret_data_member1)
                  .AddRepeatedBytesSecretDataField(
                      2, &InnerStruct::repeated_secret_data_member2)
                  .BuildOrDie())
          .AddMessageField(
              2, &ParsedStruct::inner_member_2,
              ProtoParserBuilder<InnerStruct>()
                  .AddRepeatedBytesSecretDataField(
                      1, &InnerStruct::repeated_secret_data_member1)
                  .AddRepeatedBytesSecretDataField(
                      2, &InnerStruct::repeated_secret_data_member2)
                  .BuildOrDie())
          .BuildOrDie();

  ParsedStruct struct_to_serialize;
  struct_to_serialize.inner_member_1.repeated_secret_data_member1.push_back(
      util::SecretDataFromStringView(text110));
  struct_to_serialize.inner_member_1.repeated_secret_data_member1.push_back(
      util::SecretDataFromStringView(text111));
  struct_to_serialize.inner_member_1.repeated_secret_data_member1.push_back(
      util::SecretDataFromStringView(text112));
  struct_to_serialize.inner_member_1.repeated_secret_data_member2.push_back(
      util::SecretDataFromStringView(text120));
  struct_to_serialize.inner_member_2.repeated_secret_data_member1.push_back(
      util::SecretDataFromStringView(text210));

  absl::StatusOr<SecretData> serialized =
      parser.SerializeIntoSecretData(struct_to_serialize);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*serialized),
              Eq(absl::StrCat(FieldWithNumber(1).IsSubMessage(
                                  {FieldWithNumber(1).IsString(text110),
                                   FieldWithNumber(1).IsString(text111),
                                   FieldWithNumber(1).IsString(text112),
                                   FieldWithNumber(2).IsString(text120)}),
                              FieldWithNumber(2).IsSubMessage(
                                  {FieldWithNumber(1).IsString(text210)}))));
}

// Various String field variants ===============================================

struct VariousFieldStruct {
  absl::string_view string_view_member;
};

TEST(ProtoParserTest, SerializeStringView) {
  VariousFieldStruct s;
  s.string_view_member = "data which is copied";
  ProtoParser<VariousFieldStruct> parser =
      ProtoParserBuilder<VariousFieldStruct>()
          .AddBytesStringViewField(1, &VariousFieldStruct::string_view_member)
          .BuildOrDie();
  absl::StatusOr<std::string> serialized = parser.SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a14", HexEncode("data which is copied"))));
}

TEST(ProtoParserTest, ParseStringView) {
  std::string message =
      absl::StrCat(HexDecodeOrDie("0a18"), "data which is not copied");
  ProtoParser<VariousFieldStruct> parser =
      ProtoParserBuilder<VariousFieldStruct>()
          .AddBytesStringViewField(1, &VariousFieldStruct::string_view_member)
          .BuildOrDie();
  absl::StatusOr<VariousFieldStruct> parsed = parser.Parse(message);
  ASSERT_THAT(parsed.status(), IsOk());
  EXPECT_THAT(parsed->string_view_member, Eq("data which is not copied"));
  EXPECT_THAT(parsed->string_view_member.data(), Eq(&message[2]));
}

TEST(ProtoParserTest, ParseEmptyStringView) {
  ProtoParser<VariousFieldStruct> parser =
      ProtoParserBuilder<VariousFieldStruct>()
          .AddBytesStringViewField(1, &VariousFieldStruct::string_view_member)
          .BuildOrDie();
  absl::StatusOr<VariousFieldStruct> parsed = parser.Parse("");
  ASSERT_THAT(parsed.status(), IsOk());
  EXPECT_THAT(parsed->string_view_member, IsEmpty());
}

// Varint Parsing special cases ================================================

// Comments give encoding length for values < 128
enum WeirdEncodingType {
  kNormal = 1,            // Length: 1
  kPadWithZeros = 2,      // Length: 2
  kAdd2To32 = 3,          // Length: 5
  kAdd2To32PadZero = 4,   // Length: 6
  kAdd2To35 = 5,          // Length: 6
  kAdd2To64 = 6,          // Length: 10
  kAdd2To64PadZeros = 7,  // Length: 11
  kAdd2To70 = 8,          // Length: 11
};

// Encode the varint in a non-standard way.
// kNormal: usual encoding
// kPadWithZeros: make it artificially longer by adding zero bits in the end.
//                Since Varint is little endian this makes no difference.
// kAdd2To32, kAdd2To64, kAdd2To70: Adds the corresponding amount to the varint
// before encoding it (imagining we have uint128_t or such).
std::string EncodeVarintWeirdly(uint64_t value, WeirdEncodingType t) {
  std::string result;
  if (t == kAdd2To32 || t == kAdd2To32PadZero) {
    value = value + (1LL << 32);
  }
  if (t == kAdd2To35) {
    value = value + (1LL << 35);
  }
  int i = 0;
  while (i == 0 || value > 0) {
    uint64_t byte = (value) & 0x7f;
    value = (value >> 7);
    if (i == 0 && t == kAdd2To70) {
      value = value + (1LL << 63);
    }
    if (i == 0 && (t == kAdd2To64 || t == kAdd2To64PadZeros)) {
      value = value + (1LL << 57);
    }
    if (value > 0) {
      byte |= 0x80;
    }
    result.push_back(byte);
    i++;
  }
  if (t == kPadWithZeros || t == kAdd2To32PadZero || t == kAdd2To64PadZeros) {
    result.back() |= 0x80;
    result.push_back(0x00);
  }
  return result;
}

TEST(EncodeVarintWeirdly, EncodeVarintWeirdlyTest) {
  auto encode = [](uint64_t value, WeirdEncodingType t) {
    return HexEncode(EncodeVarintWeirdly(value, t));
  };

  EXPECT_THAT(encode(0, kNormal), Eq("00"));
  EXPECT_THAT(encode(0, kPadWithZeros), Eq("8000"));
  EXPECT_THAT(encode(0, kAdd2To32), Eq("8080808010"));
  EXPECT_THAT(encode(0, kAdd2To32PadZero), Eq("808080809000"));
  EXPECT_THAT(encode(0, kAdd2To35), Eq("808080808001"));
  EXPECT_THAT(encode(0, kAdd2To64), Eq("80808080808080808002"));
  EXPECT_THAT(encode(0, kAdd2To64PadZeros), Eq("8080808080808080808200"));
  EXPECT_THAT(encode(0, kAdd2To70), Eq("8080808080808080808001"));

  EXPECT_THAT(encode(1, kNormal), Eq("01"));
  EXPECT_THAT(encode(1, kPadWithZeros), Eq("8100"));
  EXPECT_THAT(encode(1, kAdd2To32), Eq("8180808010"));
  EXPECT_THAT(encode(1, kAdd2To32PadZero), Eq("818080809000"));
  EXPECT_THAT(encode(1, kAdd2To35), Eq("818080808001"));
  EXPECT_THAT(encode(1, kAdd2To64), Eq("81808080808080808002"));
  EXPECT_THAT(encode(1, kAdd2To64PadZeros), Eq("8180808080808080808200"));
  EXPECT_THAT(encode(1, kAdd2To70), Eq("8180808080808080808001"));
}

TEST(ProtoParserTest, VarintInTagSuccess) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ParsedStruct s;

  // Field #1, Wiretype kVarint
  uint64_t field_num_wiretype = 0x08;

  std::string field_value = HexDecodeOrDie("01");
  for (WeirdEncodingType t : {kNormal, kPadWithZeros, kAdd2To32}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(EncodeVarintWeirdly(field_num_wiretype, t), field_value);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.uint32_field1(), Eq(1));

    absl::StatusOr<ParsedStruct> parsed = parser.Parse(serialization);
    ASSERT_THAT(parsed, IsOk());
    EXPECT_THAT(parsed->uint32_member_1, Eq(1));
  }
}

TEST(ProtoParserTest, VarintInTagFails) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(1, &ParsedStruct::string_member_1)
          .BuildOrDie();
  ParsedStruct s;

  // Field #1, wire type kVarint
  uint64_t field_num_wiretype = 0x08;

  std::string field_value = HexDecodeOrDie("01");
  for (WeirdEncodingType t :
       {kAdd2To32PadZero, kAdd2To35, kAdd2To64, kAdd2To64PadZeros, kAdd2To70}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(EncodeVarintWeirdly(field_num_wiretype, t), field_value);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
    EXPECT_THAT(parser.Parse(serialization), Not(IsOk()));
  }
}

TEST(ProtoParserTest, VarintAsValueNormal) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .BuildOrDie();

  // Field #1, wire type kVarint
  std::string wirtype_and_fieldnum = HexDecodeOrDie("08");

  uint32_t value = 1;
  for (WeirdEncodingType t : {kNormal, kPadWithZeros, kAdd2To32,
                              kAdd2To32PadZero, kAdd2To35, kAdd2To64}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(wirtype_and_fieldnum, EncodeVarintWeirdly(value, t));
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.uint32_field1(), Eq(value));

    absl::StatusOr<ParsedStruct> parsed = parser.Parse(serialization);
    ASSERT_THAT(parsed.status(), IsOk());
    EXPECT_THAT(parsed->uint32_member_1, Eq(value));
  }
}

TEST(ProtoParserTest, VarintAsValueFailsWith12Bytes) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .BuildOrDie();

  // Field #1, wire type kVarint
  std::string wirtype_and_fieldnum = HexDecodeOrDie("08");
  uint32_t value = 1;
  std::string field_value = HexDecodeOrDie("01");
  for (WeirdEncodingType t : {kAdd2To64PadZeros, kAdd2To70}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(wirtype_and_fieldnum, EncodeVarintWeirdly(value, t));
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
    EXPECT_THAT(parser.Parse(serialization), Not(IsOk()));
  }
}

TEST(ProtoParserTest, VarintAsLength) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .BuildOrDie();

  // Field #3, wire type kLengthDelimited
  std::string wirtype_and_fieldnum = HexDecodeOrDie("1a");

  uint32_t length = 1;

  std::string contents = "A";
  for (WeirdEncodingType t : {kNormal, kPadWithZeros}) {
    SCOPED_TRACE(t);
    std::string serialization = absl::StrCat(
        wirtype_and_fieldnum, EncodeVarintWeirdly(length, t), contents);

    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.bytes_field1(), Eq(contents));

    absl::StatusOr<ParsedStruct> parsed = parser.Parse(serialization);
    ASSERT_THAT(parsed, IsOk());
    EXPECT_THAT(parsed->string_member_1, Eq("A"));
  }
}

TEST(ProtoParserTest, VarintAsLengthFailureCases) {
  ProtoTestProto proto_test_proto;
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .BuildOrDie();

  // Field #3, wire type kLengthDelimited
  std::string wirtype_and_fieldnum = HexDecodeOrDie("1a");

  uint32_t length = 1;

  std::string contents = "A";
  for (WeirdEncodingType t : {kAdd2To64, kAdd2To70}) {
    SCOPED_TRACE(t);
    std::string serialization = absl::StrCat(
        wirtype_and_fieldnum, EncodeVarintWeirdly(length, t), contents);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
    EXPECT_THAT(parser.Parse(serialization), Not(IsOk()));
  }
}

// BuildOrDie ==================================================================
TEST(ProtoParserTest, BuildOrDieWorksIfNoError) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  (void)parser;
}

TEST(ProtoParserDeathTest, DiesOnError) {
  ASSERT_DEATH(
      {
        ProtoParserBuilder<ParsedStruct>()
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_2)
            .BuildOrDie();
      },
      "");
}
// Skip Group handling =========================================================
/* 3b: start group (field #7): 3 + 7 * 8 = 59 = 0x3b */
/* 3c:   end group (field #7): 4 + 7 * 8 = 60 = 0x3c */
/* 43: start group (field #8): 3 + 8 * 8 = 59 = 0x43 */
/* 44:   end group (field #8): 4 + 8 * 8 = 60 = 0x44 */
TEST(ProtoParserTest, GroupSkipTest) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string empty_with_group = HexDecodeOrDie("3b3c");

  EXPECT_TRUE(proto_test_proto.ParseFromString(empty_with_group));
  EXPECT_THAT(parser.Parse(empty_with_group).status(), IsOk());
}

TEST(ProtoParserTest, GroupSkipTestWrongEndTag) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string empty_with_group = HexDecodeOrDie("3b44");

  EXPECT_FALSE(proto_test_proto.ParseFromString(empty_with_group));
  EXPECT_THAT(parser.Parse(empty_with_group), Not(IsOk()));
}

// In group "7", if a (field#,varint) of the original message is given,
// it's of course *not* part of the outer message:
TEST(ProtoParserTest, FieldsInGroupAreIgnored) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string empty_with_group = HexDecodeOrDie("3b08083c");

  EXPECT_TRUE(proto_test_proto.ParseFromString(empty_with_group));
  EXPECT_THAT(proto_test_proto.uint32_field1(), Eq(0));

  absl::StatusOr<ParsedStruct> parsed_struct = parser.Parse(empty_with_group);
  ASSERT_THAT(parsed_struct.status(), IsOk());
  EXPECT_THAT(parsed_struct->uint32_member_1, Eq(0));
}

TEST(ProtoParserTest, MultinestGroupSkipTest) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string properly_nested_groups = HexDecodeOrDie(
      absl::StrCat("3b", "43", "44", "3b", "3b", "3c", "3c", "3c"));

  EXPECT_TRUE(proto_test_proto.ParseFromString(properly_nested_groups));
  EXPECT_THAT(parser.Parse(properly_nested_groups).status(), IsOk());
}

TEST(ProtoParserTest, GroupNotClosedTest) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string group_not_closed_string = HexDecodeOrDie("3b");

  EXPECT_FALSE(proto_test_proto.ParseFromString(group_not_closed_string));
  EXPECT_THAT(parser.Parse(group_not_closed_string), Not(IsOk()));
}

TEST(ProtoParserTest, GroupWronglyNestedSkipTest) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string wrongly_nested = HexDecodeOrDie("3b433c44");

  EXPECT_FALSE(proto_test_proto.ParseFromString(wrongly_nested));
  EXPECT_THAT(parser.Parse(wrongly_nested), Not(IsOk()));
}

TEST(ProtoParserTest, GroupSkipTestParseAfter) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string group_then_varintfield1_is5 = HexDecodeOrDie("3b3c0805");

  EXPECT_TRUE(proto_test_proto.ParseFromString(group_then_varintfield1_is5));
  EXPECT_THAT(proto_test_proto.uint32_field1(), Eq(5));

  absl::StatusOr<ParsedStruct> parsed_struct =
      parser.Parse(group_then_varintfield1_is5);
  ASSERT_THAT(parsed_struct.status(), IsOk());
  EXPECT_THAT(parsed_struct->uint32_member_1, Eq(5));
}

TEST(ProtoParserTest, SkipGroupLimitLower) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>().BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string thousand_sgroups = std::string(100, 0x3b);
  std::string thousand_egroups = std::string(100, 0x3c);
  std::string valid = absl::StrCat(thousand_sgroups, thousand_egroups);
  EXPECT_TRUE(proto_test_proto.ParseFromString(valid));
  EXPECT_THAT(parser.Parse(valid), IsOk());
}

TEST(ProtoParserTest, SkipGroupLimitUpper) {
  ProtoParser<ParsedStruct> parser =
      ProtoParserBuilder<ParsedStruct>().BuildOrDie();
  ProtoTestProto proto_test_proto;
  std::string thousand_sgroups = std::string(101, 0x3b);
  std::string thousand_egroups = std::string(101, 0x3c);
  std::string valid = absl::StrCat(thousand_sgroups, thousand_egroups);
  EXPECT_FALSE(proto_test_proto.ParseFromString(valid));
  EXPECT_THAT(parser.Parse(valid), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
