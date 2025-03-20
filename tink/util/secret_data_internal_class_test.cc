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

#include <cstdint>
#include <cstring>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace util {
namespace internal {
namespace {

using ::crypto::tink::internal::SecretBuffer;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Lt;
using ::testing::Not;

constexpr absl::string_view kTestData = "123";
constexpr absl::crc32c_t kTestDataCrc = absl::crc32c_t(0x107b2fb2);
constexpr absl::string_view kNextTestData = "456";
constexpr absl::crc32c_t kNextTestDataCrc = absl::crc32c_t(0x6478c48f);

TEST(SecretDataInternalClassTest, DefaultCtor) {
  SecretDataInternalClass data;
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.begin(), Eq(data.end()));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(absl::crc32c_t(0)));
  SecretDataInternalClass other;
  EXPECT_TRUE(data == other);
  EXPECT_FALSE(data != other);
}

TEST(SecretDataInternalClassTest, ValueCtor) {
  SecretDataInternalClass data(0, 123);
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(absl::crc32c_t(0)));
  SecretDataInternalClass other(4, 123);
  EXPECT_THAT(other.size(), Eq(4));
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(absl::crc32c_t(0x33a1e328)));
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
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
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
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(kTestDataCrc));
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
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  SecretDataInternalClass other = std::move(data);
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, MoveAssign) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  SecretDataInternalClass other;
  EXPECT_TRUE(other.empty());
  other = std::move(data);
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataInternalClassTest, AsStringView) {
  SecretDataInternalClass data =
      SecretDataInternalClassFromStringView(kTestData);
  EXPECT_THAT(data.AsStringView(), Eq(kTestData));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
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
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(absl::crc32c_t(kNextTestDataCrc)));
  for (size_t i = 0; i < kTestData.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(absl::crc32c_t(kTestDataCrc)));
}

TEST(SecretDataInternalClassDeathTest, IterationOutOfBounds) {
  SecretDataInternalClass secret_data =
      SecretDataInternalClassFromStringView("Hello world!");
  EXPECT_DEATH(secret_data[secret_data.size()],
               testing::HasSubstr("operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[secret_data.size() + 1],
               testing::HasSubstr("operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[-1],
               testing::HasSubstr("operator[] pos out of bounds"));
  // R-value overload.
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(std::move(secret_data)[secret_data_size],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(std::move(secret_data)[secret_data_size + 1],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
  {
    SecretDataInternalClass secret_data =
        SecretDataInternalClassFromStringView("Hello world!");
    EXPECT_DEATH(std::move(secret_data)[-1],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
}

TEST(SecretDataInternalClassTest, StringViewConstructor) {
  absl::string_view view = "some data";
  SecretDataInternalClass c(view);
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c(view)));
}

TEST(SecretDataInternalClassTest, SpanConstructor) {
  absl::string_view view = "some data";
  SecretDataInternalClass c(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(view.data()), view.size()));
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c(view)));
}

TEST(SecretDataInternalClassTest, FromSecretBuffer) {
  SecretBuffer buffer("some data");
  SecretDataInternalClass c(buffer);
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("some data")));
}

TEST(SecretDataInternalClassTest, FromSecretBufferMove) {
  SecretBuffer buffer("some data");
  SecretDataInternalClass c(std::move(buffer));
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("some data")));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(buffer.AsStringView(), Eq(""));
}

TEST(SecretDataInternalClassTest, ToSecretBuffer) {
  SecretDataInternalClass c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = c.AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  EXPECT_THAT(c.AsStringView(), Eq("arbitrary data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("arbitrary data")));
}

TEST(SecretDataInternalClassTest, ToSecretBufferMove) {
  SecretDataInternalClass c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = std::move(c).AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(c.AsStringView(), Eq(""));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
}

TEST(SecretDataInternalClassTest, ValidateCrc32cFailsIfDataIsCorrupted) {
  auto c = SecretDataInternalClass(SecretBuffer(kTestData));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  // Corrupt the data.
  const_cast<uint8_t*>(c.data())[0] ^= 1;
  EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
}

TEST(SecretDataInternalClassTest, Crc32cIsZeroIfDataIsEmpty) {
  SecretDataInternalClass c;
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
}

TEST(SecretDataInternalClassTest, Equals) {
  auto c = SecretDataInternalClass(SecretBuffer(kTestData));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));

  // Make a copy.
  SecretDataInternalClass c_copy = c;
  EXPECT_THAT(c, Eq(c_copy));
  EXPECT_THAT(c_copy.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c_copy.GetCrc32c(), Eq(kTestDataCrc));

  // Copy with different buffer capacity.
  SecretBuffer buffer = c.AsSecretBuffer();
  buffer.reserve(100);
  SecretDataInternalClass c_copy2(std::move(buffer));
  EXPECT_THAT(c, Eq(c_copy2));
  EXPECT_THAT(c.capacity(), Lt(c_copy2.capacity()));
  EXPECT_THAT(c_copy2.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c_copy2.GetCrc32c(), Eq(kTestDataCrc));

  // Truncated buffer.
  SecretBuffer buffer2(absl::StrCat(kTestData, kTestData));
  buffer2.resize(kTestData.size());
  SecretDataInternalClass c_copy3(std::move(buffer2));
  EXPECT_THAT(c, Eq(c_copy3));
  EXPECT_THAT(c.capacity(), Lt(c_copy3.capacity()));
  EXPECT_THAT(c_copy3.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c_copy3.GetCrc32c(), Eq(kTestDataCrc));

  // Corrupt the data.
  const_cast<uint8_t*>(c.data())[0] ^= 1;
  EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  // The are no longer equal.
  EXPECT_THAT(c, Not(Eq(c_copy)));
}

TEST(SecretDataInternalClassTest, ConstructorWithCrc) {
  {
    SecretDataInternalClass c(SecretBuffer(kTestData), kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  {
    SecretDataInternalClass c(kTestData, kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  {
    SecretDataInternalClass c(
        absl::MakeSpan(reinterpret_cast<const uint8_t*>(kTestData.data()),
                       kTestData.size()),
        kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  // Empty buffer.
  {
    SecretDataInternalClass c(SecretBuffer(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretDataInternalClass c(absl::string_view(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretDataInternalClass c(absl::Span<const uint8_t>(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
}

TEST(SecretDataInternalClassTest, ValidateCrc32cFailsWithWrongGivenCrc) {
  {
    SecretDataInternalClass c(SecretBuffer(kTestData), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  {
    SecretDataInternalClass c(kTestData, absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  {
    SecretDataInternalClass c(
        absl::MakeSpan(reinterpret_cast<const uint8_t*>(kTestData.data()),
                       kTestData.size()),
        absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  // Empty buffer ignores the CRC32C parameter and always returns 0.
  {
    SecretDataInternalClass c(SecretBuffer(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretDataInternalClass c(absl::string_view(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretDataInternalClass c(absl::Span<const uint8_t>(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
}

}  // namespace
}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto
