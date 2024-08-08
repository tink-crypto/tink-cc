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

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_test_proto.pb.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::StatusOr;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::Test;

constexpr int32_t kUint32Field1Tag = 1;
constexpr int32_t kUint32Field2Tag = 2;
constexpr int32_t kBytesField1Tag = 3;
constexpr int32_t kBytesField2Tag = 4;
constexpr int32_t kInnerMessageField = 10;
constexpr int32_t kUint32FieldWithLargeTag = 536870911;

struct InnerStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
};

struct ParsedStruct {
  uint32_t uint32_member_1;
  uint32_t uint32_member_2;
  std::string string_member_1;
  std::string string_member_2;
  SecretData secret_data_member_1;
  SecretData secret_data_member_2;
  InnerStruct inner_member_1;
};

// SERIALIZATION TESTS =========================================================
TEST(ProtoParserTest, SingleUint32Works) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);

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

TEST(ProtoParserTest, SingleBytesFieldStringWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");

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
  proto.set_bytes_field_1("some bytes field");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
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
  proto.set_bytes_field_1("some bytes field");
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
  proto.set_bytes_field_1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  StatusIs(absl::StatusCode::kInvalidArgument,
           HasSubstr("exceeds remaining input"));
}

TEST(ProtoParserTest, MultipleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  proto.set_bytes_field_2("another bytes field");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_2,
                                   InsecureSecretKeyAccess::Get())
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
  proto.set_uint32_field_1(0xfe84becc);
  proto.set_uint32_field_2(445533);

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
  proto1.set_uint32_field_1(1);

  ProtoTestProto proto2;
  proto2.set_uint32_field_2(2);

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
  proto.mutable_inner_proto_field_1()->set_inner_proto_uint32_field_3(123);

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
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
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
    proto.set_uint32_field_1(v);
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

TEST(ProtoParserTest, FailsOn5ByteVarintUint32) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This would work if we parsed it as a Uint64 field)
  std::string serialization = test::HexDecodeOrDie("08ffffffff7f");
  ASSERT_THAT(serialization.size(), Eq(1 + 5));
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  EXPECT_THAT(parser->Parse(serialization).status(), Not(IsOk()));
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
  proto1.mutable_inner_proto_field_1()->set_inner_proto_uint32_field_1(77);
  proto1.mutable_inner_proto_field_1()->set_inner_proto_uint32_field_2(66);

  ProtoTestProto proto2;
  proto2.mutable_inner_proto_field_1()->set_inner_proto_uint32_field_2(55);

  std::string serialized =
      absl::StrCat(proto1.SerializeAsString(), proto2.SerializeAsString());

  ProtoTestProto parsed_proto;
  ASSERT_THAT(parsed_proto.ParseFromString(serialized), IsTrue());
  // The 77 from the first instance stays
  EXPECT_THAT(parsed_proto.inner_proto_field_1().inner_proto_uint32_field_1(),
              Eq(77));
  // The 55 is overwritten
  EXPECT_THAT(parsed_proto.inner_proto_field_1().inner_proto_uint32_field_2(),
              Eq(55));

  absl::StatusOr<ParsedStruct> parsed = parser->Parse(serialized);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->inner_member_1.uint32_member_1, Eq(77));
  EXPECT_THAT(parsed->inner_member_1.uint32_member_2, Eq(55));
}

// Found by a prototype fuzzer.
TEST(ProtoParserTest, Regression1) {
  std::string serialization = HexDecodeOrDie("a20080808080808080808000");

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(4, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
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
          .AddBytesSecretDataField(4, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
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

TEST(ProtoParserTest, SerializeIntoSecretData) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
      .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<crypto::tink::util::SecretData> serialized =
      parser->SerializeIntoSecretData(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(SecretDataAsStringView(*serialized),
  Eq(HexDecodeOrDie("087a")));
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

TEST(ProtoParserTest, SerializeSecretDataField) {
  ParsedStruct s;
  std::string data = "This is some string data of arbitrary length";
  s.secret_data_member_1 = util::SecretDataFromStringView(data);
  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a2c", HexEncode(data))));
}

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

TEST(ProtoParserTest, SerializeEmpty) {
  ParsedStruct s;
  s.uint32_member_1 = 0;
  s.string_member_1 = "";
  s.secret_data_member_1 = util::SecretDataFromStringView("");
  s.inner_member_1.uint32_member_1 = 0;

  absl::StatusOr<ProtoParser<InnerStruct>> inner_parser =
      ProtoParserBuilder<InnerStruct>()
          .AddUint32Field(123456, &InnerStruct::uint32_member_1)
          .Build();
  ASSERT_THAT(inner_parser.status(), IsOk());

  absl::StatusOr<ProtoParser<ParsedStruct>> parser =
      ProtoParserBuilder<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddBytesStringField(2, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(3, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .AddMessageField<InnerStruct>(kInnerMessageField,
                                        &ParsedStruct::inner_member_1,
                                        *std::move(inner_parser))
          .Build();
  ASSERT_THAT(parser.status(), IsOk());
  absl::StatusOr<std::string> serialized = parser->SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(""));
}

// Varint Parsing special cases ================================================

enum WeirdEncodingType {
  kNormal = 1,
  kPadWithZeros = 2,
  kAdd2To32 = 3,
  kAdd2To64 = 4,
  kAdd2To70 = 5,
};

// Encode the varint in a non-standard way.
// kNormal: usual encoding
// kPadWithZeros: make it artificially longer by adding zero bits in the end.
//                Since Varint is little endian this makes no difference.
// kAdd2To32, kAdd2To64, kAdd2To70: Adds the corresponding amount to the varint
// before encoding it (imagining we have uint128_t or such).
std::string EncodeVarintWeirdly(uint64_t value, WeirdEncodingType t) {
  std::string result;
  if (t == kAdd2To32) {
    value = value + (1LL << 32);
  }
  int i = 0;
  while (i == 0 || value > 0) {
    uint64_t byte = (value) & 0x7f;
    value = (value >> 7);
    if (i == 0 && t == kAdd2To70) {
      value = value + (1LL << 63);
    }
    if (i == 0 && t == kAdd2To64) {
      value = value + (1LL << 57);
    }
    if (value > 0) {
      byte |= 0x80;
    }
    result.push_back(byte);
    i++;
  }
  if (t == kPadWithZeros) {
    result.back() |= 0x80;
    result.push_back(0x00);
  }
  return result;
}

TEST(EncodeVarintWeirdly, EncodeVarintWeirdlyTest) {
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(0, kNormal)), Eq("00"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(0, kPadWithZeros)), Eq("8000"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(0, kAdd2To32)), Eq("8080808010"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(0, kAdd2To64)),
              Eq("80808080808080808002"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(0, kAdd2To70)),
              Eq("8080808080808080808001"));

  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(1, kNormal)), Eq("01"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(1, kPadWithZeros)), Eq("8100"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(1, kAdd2To32)), Eq("8180808010"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(1, kAdd2To64)),
              Eq("81808080808080808002"));
  EXPECT_THAT(HexEncode(EncodeVarintWeirdly(1, kAdd2To70)),
              Eq("8180808080808080808001"));
}

TEST(ProtoParserTest, VarintInTagSuccess) {
  ProtoTestProto proto_test_proto;

  // Field #1, Wiretype kVarint
  uint64_t field_num_wiretype = 0x08;

  std::string field_value = HexDecodeOrDie("01");
  for (WeirdEncodingType t : {kNormal, kPadWithZeros, kAdd2To32}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(EncodeVarintWeirdly(field_num_wiretype, t), field_value);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.uint32_field_1(), Eq(1));
  }
}

TEST(ProtoParserTest, VarintInTagFails) {
  ProtoTestProto proto_test_proto;

  // Field #1, wire type kVarint
  uint64_t field_num_wiretype = 0x08;

  std::string field_value = HexDecodeOrDie("01");
  for (WeirdEncodingType t : {kAdd2To64, kAdd2To70}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(EncodeVarintWeirdly(field_num_wiretype, t), field_value);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
  }
}

TEST(ProtoParserTest, VarintAsValueNormal) {
  ProtoTestProto proto_test_proto;

  // Field #1, wire type kVarint
  std::string wirtype_and_fieldnum = HexDecodeOrDie("08");

  uint32_t value = 1;
  for (WeirdEncodingType t : {kNormal, kPadWithZeros, kAdd2To32, kAdd2To64}) {
    SCOPED_TRACE(t);
    std::string serialization =
        absl::StrCat(wirtype_and_fieldnum, EncodeVarintWeirdly(value, t));
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.uint32_field_1(), Eq(value));
  }
}

TEST(ProtoParserTest, VarintAsValueAddTwoToSeventy) {
  ProtoTestProto proto_test_proto;

  // Field #1, wire type kVarint
  std::string wirtype_and_fieldnum = HexDecodeOrDie("08");

  uint32_t value = 1;
  std::string serialization =
      absl::StrCat(wirtype_and_fieldnum, EncodeVarintWeirdly(value, kAdd2To70));
  EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
}

TEST(ProtoParserTest, VarintAsLength) {
  ProtoTestProto proto_test_proto;

  // Field #3, wire type kLengthDelimited
  std::string wirtype_and_fieldnum = HexDecodeOrDie("1a");

  uint32_t length = 1;

  std::string contents = "A";
  for (WeirdEncodingType t : {kNormal, kPadWithZeros}) {
    SCOPED_TRACE(t);
    std::string serialization = absl::StrCat(
        wirtype_and_fieldnum, EncodeVarintWeirdly(length, t), contents);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsTrue());
    EXPECT_THAT(proto_test_proto.bytes_field_1(), Eq(contents));
  }
}

TEST(ProtoParserTest, VarintAsLengthFailureCases) {
  ProtoTestProto proto_test_proto;

  // Field #3, wire type kLengthDelimited
  std::string wirtype_and_fieldnum = HexDecodeOrDie("1a");

  uint32_t length = 1;

  std::string contents = "A";
  for (WeirdEncodingType t : {kAdd2To64, kAdd2To70}) {
    SCOPED_TRACE(t);
    std::string serialization = absl::StrCat(
        wirtype_and_fieldnum, EncodeVarintWeirdly(length, t), contents);
    EXPECT_THAT(proto_test_proto.ParseFromString(serialization), IsFalse());
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
