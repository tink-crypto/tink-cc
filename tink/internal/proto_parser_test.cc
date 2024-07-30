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
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
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

TEST(ProtoParserTest, SingleUint32Works) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);

  uint32_t value = 0;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value)
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(value, Eq(123));
}

TEST(ProtoParserTest, SingleBytesFieldStringWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");

  std::string value;
  EXPECT_THAT(ProtoParser()
                  .AddBytesStringField(kBytesField1Tag, value)
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(value, Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");

  SecretData value;
  EXPECT_THAT(ProtoParser()
                  .AddBytesSecretDataField(kBytesField1Tag, value,
                                           InsecureSecretKeyAccess::Get())
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(SecretDataAsStringView(value), Eq("some bytes field"));
}

TEST(ProtoParserTest, SingleBytesFieldStringLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  std::string value;
  EXPECT_THAT(ProtoParser()
                  .AddBytesStringField(kBytesField1Tag, value)
                  .Parse(serialized_proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("exceeds remaining input")));
}

TEST(ProtoParserTest, SingleBytesFieldSecretDataTooLongDataFails) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  std::string serialized_proto = proto.SerializeAsString();
  serialized_proto.resize(serialized_proto.size() - 1);

  SecretData value;
  EXPECT_THAT(ProtoParser()
                  .AddBytesSecretDataField(kBytesField1Tag, value,
                                           InsecureSecretKeyAccess::Get())
                  .Parse(serialized_proto),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("exceeds remaining input")));
}

TEST(ProtoParserTest, MultipleBytesFieldSecretDataWorks) {
  ProtoTestProto proto;
  proto.set_bytes_field_1("some bytes field");
  proto.set_bytes_field_2("another bytes field");

  SecretData value1;
  SecretData value2;
  EXPECT_THAT(ProtoParser()
                  .AddBytesSecretDataField(kBytesField1Tag, value1,
                                           InsecureSecretKeyAccess::Get())
                  .AddBytesSecretDataField(kBytesField2Tag, value2,
                                           InsecureSecretKeyAccess::Get())
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(SecretDataAsStringView(value1), Eq("some bytes field"));
  EXPECT_THAT(SecretDataAsStringView(value2), Eq("another bytes field"));
}

TEST(ProtoParserTest, MultipleUint32Work) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(0xfe84becc);
  proto.set_uint32_field_2(445533);

  uint32_t value1 = 0;
  uint32_t value2 = 0;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value1)
                  .AddUint32Field(kUint32Field2Tag, value2)
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(value1, Eq(0xfe84becc));
  EXPECT_THAT(value2, Eq(445533));
}

TEST(ProtoParserTest, MultipleUint32OrderIsIgnored) {
  ProtoTestProto proto1;
  proto1.set_uint32_field_1(1);

  ProtoTestProto proto2;
  proto2.set_uint32_field_2(2);

  std::string serialized =
      absl::StrCat(proto2.SerializeAsString(), proto1.SerializeAsString());
  uint32_t value1 = 0;
  uint32_t value2 = 0;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value1)
                  .AddUint32Field(kUint32Field2Tag, value2)
                  .Parse(serialized),
              IsOk());

  EXPECT_THAT(value1, Eq(1));
  EXPECT_THAT(value2, Eq(2));
}

TEST(ProtoParserTest, EmptyMessageAlwaysWorks) {
  uint32_t value1 = 0;
  uint32_t value2 = 0;
  std::string value3;
  SecretData value4;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value1)
                  .AddUint32Field(kUint32Field2Tag, value2)
                  .Parse(""),
              IsOk());

  EXPECT_THAT(value1, Eq(0));
  EXPECT_THAT(value2, Eq(0));
}

TEST(ProtoParserTest, FailsIfFieldIsRepeated) {
  uint32_t value1 = 0;
  uint32_t value2 = 0;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value1)
                  .AddUint32Field(kUint32Field1Tag, value2)
                  .Parse(""),
              Not(IsOk()));
}

TEST(ProtoParserTest, ClearsValuesOnParse) {
  uint32_t value1 = 1;
  SecretData value2 = SecretDataFromStringView("before");
  std::string value3 = "also before";
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32Field1Tag, value1)
                  .AddBytesSecretDataField(kBytesField1Tag, value2,
                                           InsecureSecretKeyAccess::Get())
                  .AddBytesStringField(kBytesField2Tag, value3)
                  .Parse(""),
              IsOk());
  EXPECT_THAT(value1, Eq(0));
  EXPECT_THAT(SecretDataAsStringView(value2), Eq(""));
  EXPECT_THAT(value3, IsEmpty());
}

TEST(ProtoParserTest, VarintUint32Parsing) {
  ProtoTestProto proto;
  for (uint32_t v :
       std::vector<uint32_t>({0, 0x01, 0x7f, 0xff, 0x3a22, 0xb084bbbe,
                              0x7fffffff, 0x80000000, 0xffffffff})) {
    SCOPED_TRACE(v);
    uint32_t parse_result = 0;
    proto.set_uint32_field_1(v);
    EXPECT_THAT(ProtoParser()
                    .AddUint32Field(kUint32Field1Tag, parse_result)
                    .Parse(proto.SerializeAsString()),
                IsOk());
    EXPECT_THAT(parse_result, Eq(v));
  }
}

TEST(ProtoParserTest, MaxTagNumber) {
  ProtoTestProto proto;
  proto.set_uint32_field_with_large_tag(777);

  uint32_t value = 0;
  EXPECT_THAT(ProtoParser()
                  .AddUint32Field(kUint32FieldWithLargeTag, value)
                  .Parse(proto.SerializeAsString()),
              IsOk());

  EXPECT_THAT(value, Eq(777));
}

TEST(ProtoParserTest, FailsOnEmptyVarint) {
  uint32_t value = 0;
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t.
  std::string serialization = test::HexDecodeOrDie("08");
  EXPECT_THAT(
      ProtoParser().AddUint32Field(/*tag = */ 1, value).Parse(serialization),
      Not(IsOk()));
}

TEST(ProtoParserTest, FailsOn11ByteVarint) {
  uint32_t value = 0;
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This fails already in varint 64 parsing because it is too
  // long.)
  std::string serialization = test::HexDecodeOrDie("08ffffffffffffffffffffff");
  ASSERT_THAT(serialization.size(), Eq(1 + 11));
  EXPECT_THAT(
      ProtoParser().AddUint32Field(/*tag = */ 1, value).Parse(serialization),
      Not(IsOk()));
}

TEST(ProtoParserTest, FailsOn5ByteVarintUint32) {
  uint32_t value = 0;
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t. (This would work if we parsed it as a Uint64 field)
  std::string serialization = test::HexDecodeOrDie("08ffffffff7f");
  ASSERT_THAT(serialization.size(), Eq(1 + 5));
  EXPECT_THAT(
      ProtoParser().AddUint32Field(/*tag = */ 1, value).Parse(serialization),
      Not(IsOk()));
}

TEST(ProtoParserTest, CallingParseTwiceFails) {
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);

  uint32_t value = 0;
  ProtoParser parser;
  parser.AddUint32Field(kUint32Field1Tag, value);
  EXPECT_THAT(parser.Parse(proto.SerializeAsString()), IsOk());
  EXPECT_THAT(parser.Parse(proto.SerializeAsString()), Not(IsOk()));
}

TEST(ProtoParserTest, CallingParseTwiceFailsWhenThereIsAnErrorTheFirstTime) {
  uint32_t value = 0;
  ProtoParser parser;
  parser.AddUint32Field(kUint32Field1Tag, value);
  // 08: tag 1, wire type varint -- parsing will expect another varint encoding
  // a uint32_t.
  std::string faulty_serialization = test::HexDecodeOrDie("08");
  EXPECT_THAT(parser.Parse(faulty_serialization), Not(IsOk()));
  ProtoTestProto proto;
  proto.set_uint32_field_1(123);
  EXPECT_THAT(parser.Parse(proto.SerializeAsString()), Not(IsOk()));
}

// Found by a prototype fuzzer.
TEST(ProtoParserTest, Regression1) {
  std::string serialization = HexDecodeOrDie("a20080808080808080808000");
  uint32_t uint32_field_1;
  uint32_t uint32_field_2;
  std::string bytes_field_1;
  SecretData bytes_field_2;

  EXPECT_THAT(
      ProtoParser()
          .AddUint32Field(1, uint32_field_1)
          .AddUint32Field(2, uint32_field_2)
          .AddBytesStringField(3, bytes_field_1)
          .AddBytesSecretDataField(4, bytes_field_2,
                                   InsecureSecretKeyAccess::Get())
          .Parse(serialization), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
