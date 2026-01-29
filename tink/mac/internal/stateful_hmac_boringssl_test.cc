// Copyright 2020 Google LLC
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

#include "tink/mac/internal/stateful_hmac_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::HashType;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::HexEncode;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::SizeIs;

using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;

struct TestVector {
  TestVector(std::string test_name, std::string hex_key, HashType hash_type,
             uint32_t tag_size, std::string message, std::string hex_tag)
      : test_name(test_name),
        hex_key(hex_key),
        hash_type(hash_type),
        tag_size(tag_size),
        message(message),
        hex_tag(hex_tag) {}
  std::string test_name;
  std::string hex_key;
  subtle::HashType hash_type;
  uint32_t tag_size;
  std::string message;
  std::string hex_tag;
};

using StatefulHmacBoringSslTest = testing::TestWithParam<TestVector>;

std::vector<TestVector> GetTestVectors() {
  return {
      TestVector(/*test_name=*/"EmptyMsgSha224",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA224, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"4e496054842798a861acb67a9fe85fb7"),
      TestVector(/*test_name=*/"EmptyMsgSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"07eff8b326b7798c9ccfcbdbe579489a"),
      TestVector(/*test_name=*/"EmptyMsgSha384",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA384, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"6a0fdc1c54c664ad91c7c157d2670c5d"),
      TestVector(/*test_name=*/"EmptyMsgSha512",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/16,
                 /*message=*/"",
                 /*hex_tag=*/"2fec800ca276c44985a35aec92067e5e"),
      TestVector(/*test_name=*/"EmptyMsgSha256TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/10,
                 /*message=*/"",
                 /*hex_tag=*/"07eff8b326b7798c9ccf"),
      TestVector(/*test_name=*/"EmptyMsgSha512TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/10,
                 /*message=*/"",
                 /*hex_tag=*/"2fec800ca276c44985a3"),
      TestVector(/*test_name=*/"BasicMessageSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"1d6eb74bc283f7947e92c72bd985ce6e"),
      TestVector(/*test_name=*/"BasicMessageSha512",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/16,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"72b8ff800f57f9aeec41265a29b69b6a"),
      TestVector(/*test_name=*/"BasicMessageSha256TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/10,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"1d6eb74bc283f7947e92"),
      TestVector(/*test_name=*/"BasicMessageSha512TagSize10",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA512, /*tag_size=*/10,
                 /*message=*/"Some data to test.",
                 /*hex_tag=*/"72b8ff800f57f9aeec41"),
      TestVector(/*test_name=*/"LongMessageSha224",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA224, /*tag_size=*/16,
                 /*message=*/
                 "Some very long message which can be split in "
                 "multiple ways. The contents are not really important, "
                 "but we want the message to be quite long",
                 /*hex_tag=*/"0165b6a416a44d1558816f75ff1e13f3"),
      TestVector(/*test_name=*/"LongMessageSha256",
                 /*hex_key=*/"000102030405060708090a0b0c0d0e0f",
                 /*hash_type=*/HashType::SHA256, /*tag_size=*/16,
                 /*message=*/
                 "Some very long message which can be split in "
                 "multiple ways. The contents are not really important, "
                 "but we want the message to be quite long",
                 /*hex_tag=*/"aa85d0f6f3c46330e65f814535f6ad8e"),
  };
}

TEST_P(StatefulHmacBoringSslTest, OnlyEmptyMessages) {
  TestVector test_vector = GetParam();
  if (!test_vector.message.empty()) {
    GTEST_SKIP() << "Test tests only empty messages";
  }
  absl::StatusOr<std::unique_ptr<StatefulMac>> hmac_result =
      StatefulHmacBoringSsl::New(
          test_vector.hash_type, test_vector.tag_size,
          util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  absl::StatusOr<SecretData> tag = hmac->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(SecretDataAsStringView(*tag)), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, SingleUpdate) {
  TestVector test_vector = GetParam();
  auto hmac_result = StatefulHmacBoringSsl::New(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  ASSERT_THAT(hmac->Update(test_vector.message), IsOk());
  absl::StatusOr<SecretData> tag = hmac->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(SecretDataAsStringView(*tag)), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, MultipleUpdates) {
  TestVector test_vector = GetParam();
  auto hmac_result = StatefulHmacBoringSsl::New(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  ASSERT_THAT(hmac_result, IsOk());
  auto hmac = std::move(hmac_result.value());
  absl::string_view remaining_message = test_vector.message;
  ABSL_LOG(INFO) << "Starting to update";
  while (!remaining_message.empty()) {
    int random_byte = subtle::Random::GetRandomUInt8() % 15;
    int amount_to_consume =
        std::min<int>(remaining_message.size(), random_byte);
    ABSL_LOG(INFO) << "Consuming " << amount_to_consume << " bytes";
    ASSERT_THAT(hmac->Update(remaining_message.substr(0, amount_to_consume)),
                IsOk());
    remaining_message.remove_prefix(amount_to_consume);
  }
  ABSL_LOG(INFO) << "Done updating ";
  absl::StatusOr<SecretData> tag = hmac->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(SecretDataAsStringView(*tag)), Eq(test_vector.hex_tag));
}

TEST_P(StatefulHmacBoringSslTest, MultipleUpdatesObjectFromFactory) {
  TestVector test_vector = GetParam();
  auto factory = absl::make_unique<StatefulHmacBoringSslFactory>(
      test_vector.hash_type, test_vector.tag_size,
      util::SecretDataFromStringView(HexDecodeOrDie(test_vector.hex_key)));
  absl::StatusOr<std::unique_ptr<StatefulMac>> hmac = factory->Create();
  ASSERT_THAT(hmac, IsOk());
  absl::string_view remaining_message = test_vector.message;
  while (!remaining_message.empty()) {
    int random_byte = subtle::Random::GetRandomUInt8() % 15;
    int amount_to_consume =
        std::min<int>(remaining_message.size(), random_byte);
    ASSERT_THAT((*hmac)->Update(remaining_message.substr(0, amount_to_consume)),
                IsOk());
    remaining_message.remove_prefix(amount_to_consume);
  }
  absl::StatusOr<SecretData> tag = (*hmac)->FinalizeAsSecretData();
  ASSERT_THAT(tag, IsOk());

  EXPECT_THAT(*tag, SizeIs(test_vector.tag_size));
  EXPECT_THAT(HexEncode(SecretDataAsStringView(*tag)), Eq(test_vector.hex_tag));
}

INSTANTIATE_TEST_SUITE_P(StatefulHmacBoringSslTest, StatefulHmacBoringSslTest,
                         testing::ValuesIn(GetTestVectors()),
                         [](const testing::TestParamInfo<TestVector> &info) {
                           return info.param.test_name;
                         });

TEST(StatefulHmacBoringSslTest, InvalidKeySizes) {
  size_t tag_size = 16;

  for (int keysize = 0; keysize < 65; keysize++) {
    std::string key(keysize, 'x');
    auto hmac_result =
        StatefulHmacBoringSsl::New(subtle::HashType::SHA256, tag_size,
                                   util::SecretDataFromStringView(key));
    if (keysize >= 16) {
      EXPECT_THAT(hmac_result, IsOk());
    } else {
      EXPECT_THAT(hmac_result.status(),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("invalid key size")));
    }
  }
}

class StatefulHmacBoringSslTestVectorTest
    : public ::testing::TestWithParam<std::pair<int, std::string>> {
 public:
  // Utility to simplify testing with test vectors.
  // Arguments and result are hexadecimal.
  void StatefulHmacVerifyHex(const std::string &key_hex,
                             const std::string &msg_hex,
                             const std::string &tag_hex) {
    std::string key = test::HexDecodeOrDie(key_hex);
    std::string tag = test::HexDecodeOrDie(tag_hex);
    std::string msg = test::HexDecodeOrDie(msg_hex);
    auto create_result =
        StatefulHmacBoringSsl::New(subtle::HashType::SHA1, tag.size(),
                                   util::SecretDataFromStringView(key));
    EXPECT_THAT(create_result, IsOk());
    auto hmac = std::move(create_result.value());

    auto update_result = hmac->Update(msg);
    EXPECT_THAT(update_result, IsOk());

    absl::StatusOr<SecretData> finalize_result = hmac->FinalizeAsSecretData();
    EXPECT_THAT(finalize_result, IsOk());

    EXPECT_EQ(SecretDataAsStringView(*finalize_result), tag);
  }
};

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const google::protobuf::Struct &parsed_input,
                    HashType hash_type) {
  int errors = 0;
  const google::protobuf::Value &test_groups =
      parsed_input.fields().at("testGroups");
  for (const google::protobuf::Value &test_group :
       test_groups.list_value().values()) {
    for (const google::protobuf::Value &test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      std::string comment = test_fields.at("comment").string_value();
      std::string key = GetBytesFromHexValue(test_fields.at("key"));
      std::string msg = GetBytesFromHexValue(test_fields.at("msg"));
      std::string tag = GetBytesFromHexValue(test_fields.at("tag"));
      std::string id = absl::StrCat(test_fields.at("tcId").number_value());
      std::string expected = test_fields.at("result").string_value();

      auto create_result = StatefulHmacBoringSsl::New(
          hash_type, tag.length(), SecretDataFromStringView(key));
      EXPECT_THAT(create_result, IsOk());
      auto hmac = std::move(create_result.value());

      auto update_result = hmac->Update(msg);
      EXPECT_THAT(update_result, IsOk());

      absl::StatusOr<SecretData> finalize_result = hmac->FinalizeAsSecretData();
      ABSL_CHECK_OK(finalize_result.status());
      bool success = SecretDataAsStringView(*finalize_result) == tag;
      if (success) {
        // std::string result_tag = result.value();
        if (expected == "invalid") {
          ADD_FAILURE() << "verified incorrect tag:" << id;
          errors++;
        }
      } else {
        if (expected == "valid") {
          ADD_FAILURE() << "Could not create tag for test with tcId:" << id
                        << " tag_size:" << tag.length()
                        << " key_size:" << key.length() << " error:"
                        << SecretDataAsStringView(*finalize_result);
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST(StatefulHmacBoringSslTest, TestVectors) {
  // Test Hmac with SHA256
  absl::StatusOr<google::protobuf::Struct> parsed_input_256 =
      ReadTestVectorsV1("hmac_sha256_test.json");
  ASSERT_THAT(parsed_input_256, IsOk());
  ASSERT_TRUE(WycheproofTest(*parsed_input_256, HashType::SHA256));

  // Test Hmac with SHA512
  absl::StatusOr<google::protobuf::Struct> parsed_input_sha512 =
      ReadTestVectorsV1("hmac_sha512_test.json");
  ASSERT_THAT(parsed_input_sha512, IsOk());
  ASSERT_TRUE(WycheproofTest(*parsed_input_sha512, HashType::SHA512));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
