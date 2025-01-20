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

#include <cstring>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace util {
namespace internal {
namespace {

absl::string_view SecretDataInternalClassAsStringView(
    const SecretDataInternalClass& secret) {
  return {reinterpret_cast<const char*>(secret.data()), secret.size()};
}

using ::crypto::tink::internal::SecretBuffer;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Le;
using ::testing::Lt;

constexpr absl::string_view kTestData = "123";
constexpr absl::string_view kNextTestData = "456";

TEST(SecretDataInternalClassTest, DefaultCtor) {
  SecretDataInternalClass data;
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.begin(), Eq(data.end()));
  SecretDataInternalClass other;
  EXPECT_TRUE(data == other);
  EXPECT_FALSE(data != other);
}

TEST(SecretDataInternalClassTest, ValueCtor) {
  SecretDataInternalClass data(0, 123);
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  SecretDataInternalClass other(4, 123);
  EXPECT_THAT(other.size(), Eq(4));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(123)) << i;
  }
  EXPECT_FALSE(data == other);
  EXPECT_TRUE(data != other);
}

TEST(SecretDataInternalClassTest, CopyCtor) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  SecretDataInternalClass other = data;
  ASSERT_THAT(data.size(), Eq(3));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < data.size(); ++i) {
    EXPECT_THAT(other[i], Eq(data[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, CopyAssign) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  SecretDataInternalClass other;
  EXPECT_TRUE(other.empty());
  other = data;
  EXPECT_THAT(data.size(), Eq(3));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < data.size(); ++i) {
    EXPECT_THAT(other[i], Eq(data[i])) << i;
  }
  // verify self-assignment
  other = other;
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < data.size(); ++i) {
    EXPECT_THAT(other[i], Eq(data[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, MoveCtor) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  SecretDataInternalClass other = std::move(data);
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, MoveAssign) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  SecretDataInternalClass other;
  EXPECT_TRUE(other.empty());
  other = std::move(data);
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, AsStringView) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  EXPECT_THAT(data.AsStringView(), Eq(kTestData));
}

TEST(SecretDataInternalClassTest, Resize) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  data.resize(1);
  EXPECT_FALSE(data.empty());
  ASSERT_THAT(data.size(), Eq(1));
  EXPECT_THAT(data[0], Eq(kTestData[0]));
  data.resize(5);
  ASSERT_THAT(data.size(), Eq(5));
  EXPECT_THAT(data[0], Eq(kTestData[0]));
  EXPECT_THAT(data[1], Eq(0));
  EXPECT_THAT(data[2], Eq(0));
  EXPECT_THAT(data[3], Eq(0));
  EXPECT_THAT(data[4], Eq(0));
}

TEST(SecretDataInternalClassTest, Iteration) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  EXPECT_THAT(data.size(), Eq(3));
  size_t i = 0;
  for (auto it = data.begin(); it != data.end(); ++it, ++i) {
    ASSERT_THAT(i, Lt(kTestData.size()));
    EXPECT_THAT(*it, Eq(kTestData[i])) << i;
  }
  const SecretDataInternalClass& const_view = data;
  i = 0;
  for (auto it = const_view.begin(); it != const_view.end(); ++it, ++i) {
    ASSERT_THAT(i, Lt(kTestData.size()));
    EXPECT_THAT(*it, Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, Reserve) {
  SecretDataInternalClass data;
  data.reserve(10);
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.capacity(), Ge(10));
  data.reserve(5);
  EXPECT_THAT(data.capacity(), Ge(10));
  EXPECT_THAT(data.capacity(), Le(data.max_size()));
}

TEST(SecretDataInternalClassTest, Swap) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  SecretDataInternalClass other =
      SecretDataInternalClassFromStringView(kNextTestData);
  using std::swap;
  swap(data, other);
  for (size_t i = 0; i < kNextTestData.size(); ++i) {
    EXPECT_THAT(data[i], Eq(kNextTestData[i])) << i;
  }
  for (size_t i = 0; i < kTestData.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, SubStr) {
  SecretDataInternalClass secret_data =
      SecretDataInternalClassFromStringView("Hello world!");
  SecretDataInternalClass world = secret_data.substr(strlen("Hello "));
  EXPECT_EQ(SecretDataInternalClassAsStringView(world), "world!");
  SecretDataInternalClass hello = secret_data.substr(0, strlen("Hello"));
  EXPECT_EQ(SecretDataInternalClassAsStringView(hello), "Hello");
  SecretDataInternalClass ello = secret_data.substr(1, strlen("ello"));
  EXPECT_EQ(SecretDataInternalClassAsStringView(ello), "ello");
  SecretDataInternalClass lo = secret_data.substr(3, 1000);
  EXPECT_EQ(SecretDataInternalClassAsStringView(lo), "lo world!");
  SecretDataInternalClass full = secret_data.substr(0, 1000);
  EXPECT_EQ(SecretDataInternalClassAsStringView(full), "Hello world!");
  SecretDataInternalClass other_full = secret_data.substr(0);
  EXPECT_EQ(SecretDataInternalClassAsStringView(other_full), "Hello world!");
}

TEST(SecretDataInternalClassDeathTest, IterationOutOfBounds) {
  SecretDataInternalClass secret_data =
      SecretDataInternalClassFromStringView("Hello world!");
  EXPECT_DEATH(secret_data[secret_data.size()],
               testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[secret_data.size() + 1],
               testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[-1],
               testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  // R-value overload.
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(
        std::move(secret_data)[secret_data_size],
        testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  }
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(
        std::move(secret_data)[secret_data_size + 1],
        testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  }
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    EXPECT_DEATH(
        std::move(secret_data)[-1],
        testing::HasSubstr("SecretData::operator[] pos out of bounds"));
  }
}

TEST(SecretDataInternalClassTest, SubStrRvalue) {
  SecretDataInternalClass secret_data =
      SecretDataInternalClassFromStringView("Hello world!");
  SecretDataInternalClass world =
      std::move(secret_data).substr(strlen("Hello "));
  EXPECT_EQ(SecretDataInternalClassAsStringView(world), "world!");
}

TEST(SecretDataInternalClassTest, Append) {
  SecretDataInternalClass hello =
      SecretDataInternalClassFromStringView("Hello ");
  SecretDataInternalClass world =
      SecretDataInternalClassFromStringView("world!");
  hello.append(world);
  EXPECT_EQ(SecretDataInternalClassAsStringView(hello), "Hello world!");
}

TEST(SecretDataInternalClassTest, FromSecretBuffer) {
  SecretBuffer buffer("some data");
  SecretDataInternalClass c(buffer);
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
}

TEST(SecretDataInternalClassTest, FromSecretBufferMove) {
  SecretBuffer buffer("some data");
  SecretDataInternalClass c(std::move(buffer));
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(buffer.AsStringView(), Eq(""));
}

TEST(SecretDataInternalClassTest, ToSecretBuffer) {
  SecretDataInternalClass c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = c.AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  EXPECT_THAT(c.AsStringView(), Eq("arbitrary data"));
}

TEST(SecretDataInternalClassTest, ToSecretBufferMove) {
  SecretDataInternalClass c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = std::move(c).AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(c.AsStringView(), Eq(""));
}

}  // namespace
}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto
