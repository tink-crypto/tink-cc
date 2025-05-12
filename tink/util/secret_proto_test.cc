// Copyright 2021 Google LLC
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

#include "tink/util/secret_proto.h"

#include <string>
#include <utility>

#include "google/protobuf/util/message_differencer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "proto/test_proto.pb.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::crypto::tink::internal::SecretBuffer;
using ::crypto::tink::util::internal::AsSecretData;
using ::google::crypto::tink::NestedTestProto;
using ::google::crypto::tink::TestProto;
using ::google::protobuf::util::MessageDifferencer;

template <typename T>
class SecretProtoTest : public testing::Test {};

using MyTypes = ::testing::Types<NestedTestProto, TestProto>;
TYPED_TEST_SUITE(SecretProtoTest, MyTypes);

template <typename T>
T CreateProto();

template <>
TestProto CreateProto<TestProto>() {
  TestProto proto;
  proto.set_num(123);
  proto.set_str("Single proto");
  return proto;
}

template <>
NestedTestProto CreateProto<NestedTestProto>() {
  NestedTestProto proto;
  proto.mutable_a()->set_num(12);
  proto.mutable_a()->set_str("A proto");
  proto.mutable_b()->set_num(14);
  proto.mutable_b()->set_str("B proto");
  proto.set_num(42);
  proto.set_str("Main proto");
  return proto;
}

TYPED_TEST(SecretProtoTest, DefaultConstructor) {
  SecretProto<TypeParam> s;
  EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()));
}

TYPED_TEST(SecretProtoTest, Constructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
}

TYPED_TEST(SecretProtoTest, CopyConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  SecretProto<TypeParam> t(s);
  EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, SourceDestroyedAfterCopyConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  auto s = absl::make_unique<SecretProto<TypeParam>>(proto);
  SecretProto<TypeParam> t(*s);
  EXPECT_TRUE(MessageDifferencer::Equals(**s, proto));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  // Test with source destroyed after the copy
  s.reset();
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, AssignmentOperator) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> t;
  {
    SecretProto<TypeParam> s(proto);
    t = s;
    EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
    EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  }
  // Test with source destroyed after the copy
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, MoveConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  SecretProto<TypeParam> t(std::move(s));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  // NOLINTNEXTLINE: bugprone-use-after-move
  EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()) ||
              MessageDifferencer::Equals(*s, proto));
}

TYPED_TEST(SecretProtoTest, MoveAssignment) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> t;
  {
    SecretProto<TypeParam> s(proto);
    t = std::move(s);
    EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
    // NOLINTNEXTLINE: bugprone-use-after-move
    EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()) ||
                MessageDifferencer::Equals(*s, proto));
  }
  // Test with source destroyed after the move
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, FromSecretData) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretBuffer buffer;
  buffer.resize(proto.ByteSizeLong());
  ASSERT_TRUE(proto.SerializeToArray(buffer.data(), buffer.size()));
  crypto::tink::SecretData data = AsSecretData(buffer);
  StatusOr<SecretProto<TypeParam>> secret_proto =
      SecretProto<TypeParam>::ParseFromSecretData(data);
  ASSERT_TRUE(secret_proto.ok()) << secret_proto.status();
  EXPECT_TRUE(MessageDifferencer::Equals(**secret_proto, proto));
}

TYPED_TEST(SecretProtoTest, AsSecretData) {
  TypeParam proto = CreateProto<TypeParam>();
  std::string serialized = proto.SerializeAsString();
  SecretProto<TypeParam> secret_proto(proto);
  absl::StatusOr<crypto::tink::SecretData> secret_serialized =
      secret_proto.SerializeAsSecretData();
  ASSERT_TRUE(secret_serialized.ok()) << secret_serialized.status();
  EXPECT_EQ(serialized, SecretDataAsStringView(*secret_serialized));
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
