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

// SERIALIZATION TESTS =========================================================
TEST(ProtoParserTest, SingleUint32Works) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);

  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->uint32_member_1, Eq(123));
}

TEST(ProtoParserTest, SingleBytesFieldStringWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");

  std::string value;
  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(parsed->string_member_1, Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");

  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(SecretDataAsStringView(parsed->secret_data_member_1),
              Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldStringLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  EXPECT_THAT(
      ProtoParser<ParsedStruct>()
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .Parse(serialized_proto)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("exceeds remaining input")));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataTooLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  EXPECT_THAT(ProtoParser<ParsedStruct>()
                  .AddBytesSecretDataField(kBytesField1Tag,
                                           &ParsedStruct::secret_data_member_1,
                                           InsecureSecretKeyAccess::Get())
                  .Parse(serialized_proto)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("exceeds remaining input")));
}

TEST(ProtoParserTest, MultipleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  proto.set_bytes_field_2("another bytes field");

  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddBytesSecretDataField(kBytesField1Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_2,
                                   InsecureSecretKeyAccess::Get())
          .Parse(proto.SerializeAsString());
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

  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .Parse(proto.SerializeAsString());
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
  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .Parse(serialized);
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(1));
  EXPECT_THAT(parsed->uint32_member_2, Eq(2));
}

TEST(ProtoParserTest, EmptyMessageAlwaysWorks) {
  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field2Tag, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(kBytesField1Tag, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(kBytesField2Tag,
                                   &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .Parse("");
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(0));
  EXPECT_THAT(parsed->uint32_member_2, Eq(0));
  EXPECT_THAT(parsed->string_member_1, IsEmpty());
  EXPECT_THAT(parsed->secret_data_member_1, IsEmpty());
}

TEST(ProtoParserTest, FailsIfFieldIsRepeated) {
  EXPECT_THAT(
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
          .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_2)
          .Parse(""),
      Not(IsOk()));
}

TEST(ProtoParserTest, VarintUint32Parsing) {
  ProtoTestProto proto;
  for (uint32_t v :
       std::vector<uint32_t>({0, 0x01, 0x7f, 0xff, 0x3a22, 0xb084bbbe,
                              0x7fffffff, 0x80000000, 0xffffffff})) {
    SCOPED_TRACE(v);
    proto.set_uint32_field_1(v);
    absl::StatusOr<ParsedStruct> parsed =
        ProtoParser<ParsedStruct>()
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
            .Parse(proto.SerializeAsString());
    ASSERT_THAT(parsed, IsOk());
    EXPECT_THAT(parsed->uint32_member_1, Eq(v));
  }
}

TEST(ProtoParserTest, MaxTagNumber) {
  ProtoTestProto proto;
  proto.set_uint32_field_with_large_tag(777);

  absl::StatusOr<ParsedStruct> parsed =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(kUint32FieldWithLargeTag,
                          &ParsedStruct::uint32_member_1)
          .Parse(proto.SerializeAsString());
  ASSERT_THAT(parsed, IsOk());

  EXPECT_THAT(parsed->uint32_member_1, Eq(777));
}

TEST(ProtoParserTest, FailsOnEmptyVarint) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t.
  std::string serialization = test::HexDecodeOrDie("08");
  EXPECT_THAT(ProtoParser<ParsedStruct>()
                  .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
                  .Parse(serialization)
                  .status(),
              Not(IsOk()));
}

TEST(ProtoParserTest, FailsOn11ByteVarint) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This fails already in varint 64 parsing because it is too
  // long.)
  std::string serialization = test::HexDecodeOrDie("08ffffffffffffffffffffff");
  ASSERT_THAT(serialization.size(), Eq(1 + 11));
  EXPECT_THAT(ProtoParser<ParsedStruct>()
                  .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
                  .Parse(serialization)
                  .status(),
              Not(IsOk()));
}

TEST(ProtoParserTest, FailsOn5ByteVarintUint32) {
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This would work if we parsed it as a Uint64 field)
  std::string serialization = test::HexDecodeOrDie("08ffffffff7f");
  ASSERT_THAT(serialization.size(), Eq(1 + 5));
  EXPECT_THAT(ProtoParser<ParsedStruct>()
                  .AddUint32Field(/*tag = */ 1, &ParsedStruct::uint32_member_1)
                  .Parse(serialization)
                  .status(),
              Not(IsOk()));
}

// Found by a prototype fuzzer.
TEST(ProtoParserTest, Regression1) {
  std::string serialization = HexDecodeOrDie("a20080808080808080808000");

  EXPECT_THAT(
      ProtoParser<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .AddBytesStringField(3, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(4, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .Parse(serialization),
      Not(IsOk()));
}

// SERIALIZATION TESTS =========================================================
TEST(ProtoParserTest, SerializeUint32Field) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  absl::StatusOr<std::string> serialized =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(HexDecodeOrDie("087a")));
}

TEST(ProtoParserTest, SerializeIntoSecretData) {
  ParsedStruct s;
  s.uint32_member_1 = 0x7a;
  absl::StatusOr<SecretData> serialized =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .SerializeIntoSecretData(s);
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
    absl::StatusOr<std::string> serialized =
        ProtoParser<ParsedStruct>()
            .AddUint32Field(pair.second, &ParsedStruct::uint32_member_1)
            .SerializeIntoString(s);
    ASSERT_THAT(serialized, IsOk());
    EXPECT_THAT(HexEncode(*serialized), Eq(pair.first));
  }
}

TEST(ProtoParserTest, SerializeUint32Variations) {
  ParsedStruct s;
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
    absl::StatusOr<std::string> serialized =
        ProtoParser<ParsedStruct>()
            .AddUint32Field(1, &ParsedStruct::uint32_member_1)
            .SerializeIntoString(s);
    ASSERT_THAT(serialized, IsOk());
    EXPECT_THAT(HexEncode(*serialized), Eq(pair.first));
  }
}

TEST(ProtoParserTest, TwoUintFields) {
  ParsedStruct s;
  s.uint32_member_1 = 0x10;
  s.uint32_member_2 = 0xaa;
  absl::StatusOr<std::string> serialized =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddUint32Field(2, &ParsedStruct::uint32_member_2)
          .SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized), Eq("081010aa01"));
}

TEST(ProtoParserTest, SerializeStringField) {
  ParsedStruct s;
  s.string_member_1 = "This is some string data of arbitrary length";
  absl::StatusOr<std::string> serialized =
      ProtoParser<ParsedStruct>()
          .AddBytesStringField(1, &ParsedStruct::string_member_1)
          .SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a2c", HexEncode(s.string_member_1))));
}

TEST(ProtoParserTest, SerializeSecretDataField) {
  ParsedStruct s;
  std::string data = "This is some string data of arbitrary length";
  s.secret_data_member_1 = util::SecretDataFromStringView(data);
  absl::StatusOr<std::string> serialized =
      ProtoParser<ParsedStruct>()
          .AddBytesSecretDataField(1, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(HexEncode(*serialized),
              Eq(absl::StrCat("0a2c", HexEncode(data))));
}

TEST(ProtoParserTest, SerializeEmpty) {
  // TODO(b/339151111): Modify so that empty fields are not serialized.
  ParsedStruct s;
  s.uint32_member_1 = 0;
  s.string_member_1 = "";
  s.secret_data_member_1 = util::SecretDataFromStringView("");
  absl::StatusOr<std::string> serialized =
      ProtoParser<ParsedStruct>()
          .AddUint32Field(1, &ParsedStruct::uint32_member_1)
          .AddBytesStringField(2, &ParsedStruct::string_member_1)
          .AddBytesSecretDataField(3, &ParsedStruct::secret_data_member_1,
                                   InsecureSecretKeyAccess::Get())
          .SerializeIntoString(s);
  ASSERT_THAT(serialized, IsOk());
  EXPECT_THAT(*serialized, Eq(""));
}

TEST(ProtoParserTest, PermanentErrorRespected) {
    ParsedStruct s;
    s.uint32_member_1 = 0;
    s.uint32_member_2 = 0;
    EXPECT_THAT(
        ProtoParser<ParsedStruct>()
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_2)
            .SerializeIntoString(s),
        Not(IsOk()));
    EXPECT_THAT(
        ProtoParser<ParsedStruct>()
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_1)
            .AddUint32Field(kUint32Field1Tag, &ParsedStruct::uint32_member_2)
            .SerializeIntoSecretData(s),
        Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
