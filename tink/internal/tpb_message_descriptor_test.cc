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
#include "tink/internal/tpb_message_descriptor.h"
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::Test;

TEST(TpbMessageDescriptorTest, EmptyMessageGetTypeError) {
  TpbMessageDescriptor descriptor;
  EXPECT_THAT(descriptor.GetType(123), Not(IsOk()));
}

TEST(TpbMessageDescriptorTest, SingleUInt32FieldWorks) {
  TpbMessageDescriptor descriptor;
  ASSERT_THAT(descriptor.AddUint32(123), IsOk());
  EXPECT_THAT(descriptor.GetType(123),
              IsOkAndHolds(TpbMessageDescriptor::Type::kUint32));
}

TEST(TpbMessageDescriptorTest, SingleBytesFieldWorks) {
  TpbMessageDescriptor descriptor;
  ASSERT_THAT(descriptor.AddBytes(345), IsOk());
  EXPECT_THAT(descriptor.GetType(345),
              IsOkAndHolds(TpbMessageDescriptor::Type::kBytes));
}

TEST(TpbMessageDescriptorTest, SingleMessageFieldWorks) {
  TpbMessageDescriptor nested_descriptor;
  ASSERT_THAT(nested_descriptor.AddUint32(123), IsOk());
  TpbMessageDescriptor descriptor;
  ASSERT_THAT(descriptor.AddMessage(345, nested_descriptor), IsOk());
  EXPECT_THAT(descriptor.GetType(345),
              IsOkAndHolds(TpbMessageDescriptor::Type::kMessage));
  const TpbMessageDescriptor* message_descriptor =
      descriptor.GetMessage(345);
  ASSERT_THAT(message_descriptor, Not(IsNull()));
  EXPECT_THAT(message_descriptor->GetType(123),
              IsOkAndHolds(TpbMessageDescriptor::Type::kUint32));
}

TEST(TpbMessageDescriptorTest, AddExsitingFieldFails) {
  TpbMessageDescriptor descriptor;
  ASSERT_THAT(descriptor.AddUint32(123), IsOk());

  EXPECT_THAT(descriptor.AddUint32(123),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Tag 123 already exists")));
}


TEST(TpbMessageDescriptorTest, EqualityEmpty) {
  TpbMessageDescriptor m1;
  TpbMessageDescriptor m2;
  EXPECT_TRUE(m1 == m2);
  EXPECT_FALSE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, EqualitySingleUInt32) {
  TpbMessageDescriptor m1;
  TpbMessageDescriptor m2;
  ASSERT_THAT(m1.AddUint32(123), IsOk());
  ASSERT_THAT(m2.AddUint32(123), IsOk());
  EXPECT_TRUE(m1 == m2);
  EXPECT_FALSE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, EqualitySingleBytes) {
  TpbMessageDescriptor m1;
  TpbMessageDescriptor m2;
  ASSERT_THAT(m1.AddBytes(123), IsOk());
  ASSERT_THAT(m2.AddBytes(123), IsOk());
  EXPECT_TRUE(m1 == m2);
  EXPECT_FALSE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, EqualitySingleNestedMessage) {
  TpbMessageDescriptor i1;
  TpbMessageDescriptor i2;
  ASSERT_THAT(i1.AddBytes(234), IsOk());
  ASSERT_THAT(i2.AddBytes(234), IsOk());
  TpbMessageDescriptor m1;
  TpbMessageDescriptor m2;
  ASSERT_THAT(m1.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m2.AddMessage(123, i2), IsOk());
  EXPECT_TRUE(m1 == m2);
  EXPECT_FALSE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, NotEqualityToEmpty) {
  TpbMessageDescriptor m1;
  ASSERT_THAT(m1.AddUint32(123), IsOk());
  EXPECT_FALSE(m1 == TpbMessageDescriptor());
  EXPECT_TRUE(m1 != TpbMessageDescriptor());

  TpbMessageDescriptor m2;
  ASSERT_THAT(m2.AddBytes(123), IsOk());
  EXPECT_FALSE(m2 == TpbMessageDescriptor());
  EXPECT_TRUE(m2 != TpbMessageDescriptor());

  TpbMessageDescriptor m3;
  ASSERT_THAT(m3.AddMessage(123, TpbMessageDescriptor()), IsOk());
  EXPECT_FALSE(m3 == TpbMessageDescriptor());
  EXPECT_TRUE(m3 != TpbMessageDescriptor());
}

TEST(TpbMessageDescriptorTest, NotEqualityDifferentTypes) {
  TpbMessageDescriptor m1;
  ASSERT_THAT(m1.AddUint32(123), IsOk());
  TpbMessageDescriptor m2;
  ASSERT_THAT(m2.AddBytes(123), IsOk());
  EXPECT_FALSE(m1 == m2);
  EXPECT_TRUE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, NotEqualIfInnerMessageDiffers) {
  TpbMessageDescriptor i1;
  ASSERT_THAT(i1.AddUint32(123), IsOk());
  TpbMessageDescriptor i2;
  ASSERT_THAT(i2.AddBytes(123), IsOk());

  TpbMessageDescriptor m1;
  TpbMessageDescriptor m2;
  ASSERT_THAT(m1.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m2.AddMessage(123, i2), IsOk());
  EXPECT_FALSE(m1 == m2);
  EXPECT_TRUE(m1 != m2);
}

TEST(TpbMessageDescriptorTest, CopyConstructorWorks) {
  TpbMessageDescriptor i1;
  ASSERT_THAT(i1.AddUint32(123), IsOk());
  TpbMessageDescriptor i2;
  ASSERT_THAT(i2.AddBytes(123), IsOk());

  TpbMessageDescriptor m;
  ASSERT_THAT(m.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m.AddMessage(345, i2), IsOk());

  TpbMessageDescriptor m2 = m;
  EXPECT_TRUE(m == m2);
}

TEST(TpbMessageDescriptorTest, CopyAssignmentWorks) {
  TpbMessageDescriptor i1;
  ASSERT_THAT(i1.AddUint32(123), IsOk());
  TpbMessageDescriptor i2;
  ASSERT_THAT(i2.AddBytes(123), IsOk());

  TpbMessageDescriptor m;
  ASSERT_THAT(m.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m.AddMessage(345, i2), IsOk());

  TpbMessageDescriptor m2;
  m2 = m;
  EXPECT_TRUE(m == m2);
}

TEST(TpbMessageDescriptorTest, MoveConstructorWorks) {
  TpbMessageDescriptor i1;
  ASSERT_THAT(i1.AddUint32(123), IsOk());
  TpbMessageDescriptor i2;
  ASSERT_THAT(i2.AddBytes(123), IsOk());

  TpbMessageDescriptor m;
  ASSERT_THAT(m.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m.AddMessage(345, i2), IsOk());
  TpbMessageDescriptor copy = m;

  TpbMessageDescriptor m2 = std::move(copy);
  EXPECT_TRUE(m == m2);
}

TEST(TpbMessageDescriptorTest, MoveAssignmentWorks) {
  TpbMessageDescriptor i1;
  ASSERT_THAT(i1.AddUint32(123), IsOk());
  TpbMessageDescriptor i2;
  ASSERT_THAT(i2.AddBytes(123), IsOk());

  TpbMessageDescriptor m;
  ASSERT_THAT(m.AddMessage(123, i1), IsOk());
  ASSERT_THAT(m.AddMessage(345, i2), IsOk());
  TpbMessageDescriptor copy = m;

  TpbMessageDescriptor m2;
  m2 = std::move(copy);
  EXPECT_TRUE(m == m2);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
