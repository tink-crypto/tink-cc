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

struct VarintCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  uint64_t value;                       // Parsed value.
};

constexpr VarintCase kVarintCases[] = {
    {"00", 0},
    {"01", 1},
    {"7f", 127},
    {"8001", 128},
    {"a274", 14882},
    {"bef792840b", 2961488830},
    {"80e6eb9cc3c9a449", 41256202580718336ULL},
    {"9ba8f9c2bbd68085a601", 11964378330978735131ULL},
    {"80808080808080808001", /* 2^63 */ 9223372036854775808ULL },
    {"feffffffffffffffff01", /* 2^64 - 2*/ 18446744073709551614ULL },
    {"ffffffffffffffffff01", /* 2^64 - 1*/ 18446744073709551615ULL },
};

TEST(ProtoParserTest, ConsumeVarintIntoUint64DirectTest) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<uint64_t> result = ConsumeVarintIntoUint64(bytes_view);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(*result, Eq(v.value));
    EXPECT_THAT(bytes_view, IsEmpty());
  }
}

TEST(ProtoParserTest, ConsumeVarintIntoUint32DirectTest) {
  for (const VarintCase& v : kVarintCases) {
    SCOPED_TRACE(v.value);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<uint32_t> result = ConsumeVarintIntoUint32(bytes_view);
    if (v.value <= std::numeric_limits<uint32_t>::max()) {
      ASSERT_THAT(result, IsOk());
      EXPECT_THAT(*result, Eq(v.value));
      EXPECT_THAT(bytes_view, IsEmpty());
    } else {
      EXPECT_THAT(result, Not(IsOk()));
    }
  }
}

constexpr absl::string_view kHexEncodedVarintFailureCases[] = {
    "",
    // We expect canonical varints: this encodes 0 so should be encoded as "0"
    "8000",
    // This encodes 1, so should be encoded as "01".
    "8100",
    "faab",
    "f0abc99af8b2",
    // Would encode 2^64 == std::numeric_limits<uint64_t>::max() + 1
    "80808080808080808002",
     // Something clearly too big (but the same number of bytes as above)
    "ffffffffffffffffff08",
     // Varint with too many bytes.
    "ffffffffffffffffffff01",
};

TEST(ProtoParserTest, VarintParsingFailure) {
  for (absl::string_view hex_encoded_bytes : kHexEncodedVarintFailureCases) {
    SCOPED_TRACE(hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    EXPECT_THAT(ConsumeVarintIntoUint64(bytes_view), Not(IsOk()));
  }
}

struct WireTypeAndTagCase {
  absl::string_view hex_encoded_bytes;  // Encoding
  WireType wiretype;
  int tag;
};

constexpr WireTypeAndTagCase kWireTypeAndTagCases[] = {
    {"08", WireType::kVarint, 1},
    {"09", WireType::kFixed64, 1},
    {"0a", WireType::kLengthDelimited, 1},
    {"0b", WireType::kStartGroup, 1},
    {"0c", WireType::kEndGroup, 1},
    {"0d", WireType::kFixed32, 1},
    {"10", WireType::kVarint, 2},
    {"78", WireType::kVarint, 15},
    {"8001", WireType::kVarint, 16},
    {"f8ffffff0f", WireType::kVarint, 536870911},
    // Note: proto only accepts tags up to 2^29-1, so this is the largest tag,
    // but our code currently accepts higher tags.
    {"f8ffffff1f", WireType::kVarint, 1073741823},
    // Note: overflow
    {"f8ffffff7f", WireType::kVarint, -1},
};

TEST(ProtoParserTest, ConsumeIntoWireTypeAndTag) {
  for (const WireTypeAndTagCase& v : kWireTypeAndTagCases) {
    SCOPED_TRACE(v.hex_encoded_bytes);
    std::string bytes = HexDecodeOrDie(v.hex_encoded_bytes);
    absl::string_view bytes_view = bytes;
    absl::StatusOr<std::pair<WireType, int>> result =
        ConsumeIntoWireTypeAndTag(bytes_view);
    ASSERT_THAT(result, IsOk());
    EXPECT_THAT(result->first, Eq(v.wiretype));
    EXPECT_THAT(result->second, Eq(v.tag));
    EXPECT_THAT(bytes_view, IsEmpty());
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
