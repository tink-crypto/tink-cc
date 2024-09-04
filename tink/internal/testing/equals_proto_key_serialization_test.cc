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

#include "tink/internal/testing/equals_proto_key_serialization.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_testing {

namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Not;

constexpr absl::string_view kTypeUrl = "SomeArbitraryTypeUrl";

TEST(EqualsProtoKeySerialization, Equals) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key2,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1, EqualsProtoKeySerialization(*serialization2));
}

TEST(EqualsProtoKeySerialization, TypeUrlDiffers) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create("somedifferenttypeurl", serialized_key2,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1,
              Not(EqualsProtoKeySerialization(*serialization2)));
}

TEST(EqualsProtoKeySerialization, DifferentKey) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data1", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data2", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key2,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1,
              Not(EqualsProtoKeySerialization(*serialization2)));
}

TEST(EqualsProtoKeySerialization, KeyMaterialTypeDiffer) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key2,
                                    KeyData::ASYMMETRIC_PRIVATE,
                                    OutputPrefixType::LEGACY,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1,
              Not(EqualsProtoKeySerialization(*serialization2)));
}

TEST(EqualsProtoKeySerialization, DifferentOutputPrefix) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key2,
                                    KeyData::SYMMETRIC,
                                    OutputPrefixType::LEGACY,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1,
              Not(EqualsProtoKeySerialization(*serialization2)));
}

TEST(EqualsProtoKeySerialization, DifferentIdRequirement) {
  RestrictedData serialized_key1 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization1 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key1,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization1.status(), IsOk());

  RestrictedData serialized_key2 =
      RestrictedData("some key data", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization2 =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key2,
                                    KeyData::SYMMETRIC,
                                    OutputPrefixType::LEGACY,
                                    /*id_requirement=*/445566);
  ASSERT_THAT(serialization2.status(), IsOk());
  EXPECT_THAT(*serialization1,
              Not(EqualsProtoKeySerialization(*serialization2)));
}

TEST(EqualsProtoKeySerialization, EverythingDiffersToTestTheMessage) {
  RestrictedData serialized_key =
      RestrictedData("a", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("typeUrl1", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  RestrictedData expected_key =
      RestrictedData("b", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> expected =
      ProtoKeySerialization::Create("typeUrl2", expected_key,
                                    KeyData::ASYMMETRIC_PRIVATE,
                                    OutputPrefixType::LEGACY,
                                    /*id_requirement=*/445566);
  ASSERT_THAT(expected.status(), IsOk());
  // If I remove the Not, this creates currently a string with the following
  // substring:
  // Type URLS differ, expected 'typeUrl2', got 'typeUrl1',
  // Keys differ, expected 'b' (hex 62), got 'a' (hex 61),
  // KeyMaterialTypes differ, expected ASYMMETRIC_PRIVATE, got SYMMETRIC,
  // OutputPrefixType differ, expected LEGACY, got TINK,
  // IDRequirements differ, expected 445566, got 12345
  EXPECT_THAT(*serialization, Not(EqualsProtoKeySerialization(*expected)));
}

}  // namespace

}  // namespace proto_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
