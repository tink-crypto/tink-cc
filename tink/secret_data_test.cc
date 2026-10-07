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

#include "tink/secret_data.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::internal::SecretBuffer;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::Lt;
using ::testing::Not;

constexpr absl::string_view kTestData = "123";
constexpr absl::crc32c_t kTestDataCrc = absl::crc32c_t(0x107b2fb2);
constexpr absl::string_view kNextTestData = "456";
constexpr absl::crc32c_t kNextTestDataCrc = absl::crc32c_t(0x6478c48f);

TEST(SecretDataTest, DefaultCtor) {
  SecretData data;
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.begin(), Eq(data.end()));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(absl::crc32c_t(0)));
  SecretData other;
  EXPECT_TRUE(data == other);
  EXPECT_FALSE(data != other);
}

TEST(SecretDataTest, ValueCtor) {
  SecretData data(0, 123);
  EXPECT_TRUE(data.empty());
  EXPECT_THAT(data.size(), Eq(0));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(absl::crc32c_t(0)));
  SecretData other(4, 123);
  EXPECT_THAT(other.size(), Eq(4));
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(absl::crc32c_t(0x33a1e328)));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(123)) << i;
  }
  EXPECT_FALSE(data == other);
  EXPECT_TRUE(data != other);
}

TEST(SecretDataTest, CopyCtor) {
  SecretData data(kTestData);
  SecretData other = data;
  ASSERT_THAT(data.size(), Eq(3));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < data.size(); ++i) {
    EXPECT_THAT(other[i], Eq(data[i])) << i;
  }
}

TEST(SecretDataTest, CopyAssign) {
  SecretData data(kTestData);
  SecretData other;
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

TEST(SecretDataTest, MoveCtor) {
  SecretData data(kTestData);
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  SecretData other = std::move(data);
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataTest, MoveAssign) {
  SecretData data(kTestData);
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
  SecretData other;
  EXPECT_TRUE(other.empty());
  other = std::move(data);
  EXPECT_THAT(other.ValidateCrc32c(), IsOk());
  EXPECT_THAT(other.GetCrc32c(), Eq(kTestDataCrc));
  ASSERT_THAT(other.size(), Eq(3));
  for (size_t i = 0; i < other.size(); ++i) {
    EXPECT_THAT(other[i], Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataTest, AsStringView) {
  SecretData data(kTestData);
  EXPECT_THAT(data.AsStringView(), Eq(kTestData));
  EXPECT_THAT(data.ValidateCrc32c(), IsOk());
  EXPECT_THAT(data.GetCrc32c(), Eq(kTestDataCrc));
}

TEST(SecretDataTest, Iteration) {
  SecretData data(kTestData);
  EXPECT_THAT(data.size(), Eq(3));
  size_t i = 0;
  for (auto it = data.begin(); it != data.end(); ++it, ++i) {
    ASSERT_THAT(i, Lt(kTestData.size()));
    EXPECT_THAT(*it, Eq(kTestData[i])) << i;
  }
  const SecretData& const_view = data;
  i = 0;
  for (auto it = const_view.begin(); it != const_view.end(); ++it, ++i) {
    ASSERT_THAT(i, Lt(kTestData.size()));
    EXPECT_THAT(*it, Eq(kTestData[i])) << i;
  }
}

TEST(SecretDataTest, Swap) {
  SecretData data(kTestData);
  SecretData other(kNextTestData);
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

TEST(SecretDataDeathTest, IterationOutOfBounds) {
  SecretData secret_data("Hello world!");
  EXPECT_DEATH(secret_data[secret_data.size()],
               testing::HasSubstr("operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[secret_data.size() + 1],
               testing::HasSubstr("operator[] pos out of bounds"));
  EXPECT_DEATH(secret_data[-1],
               testing::HasSubstr("operator[] pos out of bounds"));
  // R-value overload.
  {
    SecretData secret_data("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(std::move(secret_data)[secret_data_size],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
  {
    SecretData secret_data("Hello world!");
    size_t secret_data_size = secret_data.size();
    EXPECT_DEATH(std::move(secret_data)[secret_data_size + 1],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
  {
    SecretData secret_data("Hello world!");
    EXPECT_DEATH(std::move(secret_data)[-1],
                 testing::HasSubstr("operator[] pos out of bounds"));
  }
}

TEST(SecretDataTest, StringViewConstructor) {
  absl::string_view view = "some data";
  SecretData c(view);
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c(view)));
}

TEST(SecretDataTest, SpanConstructor) {
  absl::string_view view = "some data";
  SecretData c(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t*>(view.data()), view.size()));
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c(view)));
}

TEST(SecretDataTest, FromSecretBuffer) {
  SecretBuffer buffer("some data");
  SecretData c(buffer);
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("some data")));
}

TEST(SecretDataTest, FromSecretBufferMove) {
  SecretBuffer buffer("some data");
  SecretData c(std::move(buffer));
  EXPECT_THAT(c.AsStringView(), Eq("some data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("some data")));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(buffer.AsStringView(), Eq(""));
}

TEST(SecretDataTest, ToSecretBuffer) {
  SecretData c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = c.AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  EXPECT_THAT(c.AsStringView(), Eq("arbitrary data"));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::ComputeCrc32c("arbitrary data")));
}

TEST(SecretDataTest, ToSecretBufferMove) {
  SecretData c(SecretBuffer("arbitrary data"));
  SecretBuffer buffer = std::move(c).AsSecretBuffer();
  EXPECT_THAT(buffer, Eq(SecretBuffer("arbitrary data")));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(c.AsStringView(), Eq(""));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
}

TEST(SecretDataTest, ValidateCrc32cFailsIfDataIsCorrupted) {
  auto c = SecretData(SecretBuffer(kTestData));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  // Corrupt the data.
  const_cast<uint8_t*>(c.data())[0] ^= 1;
  EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
}

TEST(SecretDataTest, Crc32cIsZeroIfDataIsEmpty) {
  SecretData c;
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
}

TEST(SecretDataTest, Equals) {
  auto c = SecretData(SecretBuffer(kTestData));
  EXPECT_THAT(c.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));

  // Make a copy.
  SecretData c_copy = c;
  EXPECT_THAT(c, Eq(c_copy));
  EXPECT_THAT(c_copy.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c_copy.GetCrc32c(), Eq(kTestDataCrc));

  // Copy with different buffer capacity.
  SecretBuffer buffer = c.AsSecretBuffer();
  buffer.reserve(100);
  SecretData c_copy2(std::move(buffer));
  EXPECT_THAT(c, Eq(c_copy2));
  EXPECT_THAT(c.capacity(), Lt(c_copy2.capacity()));
  EXPECT_THAT(c_copy2.ValidateCrc32c(), IsOk());
  EXPECT_THAT(c_copy2.GetCrc32c(), Eq(kTestDataCrc));

  // Truncated buffer.
  SecretBuffer buffer2(absl::StrCat(kTestData, kTestData));
  buffer2.resize(kTestData.size());
  SecretData c_copy3(std::move(buffer2));
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

TEST(SecretDataTest, ConstructorWithCrc) {
  {
    SecretData c(SecretBuffer(kTestData), kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  {
    SecretData c(kTestData, kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  {
    SecretData c(
        absl::MakeSpan(reinterpret_cast<const uint8_t*>(kTestData.data()),
                       kTestData.size()),
        kTestDataCrc);
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(kTestDataCrc));
  }
  // Empty buffer.
  {
    SecretData c(SecretBuffer(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretData c(absl::string_view(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretData c(absl::Span<const uint8_t>(), absl::crc32c_t(0));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
}

TEST(SecretDataTest, ValidateCrc32cFailsWithWrongGivenCrc) {
  {
    SecretData c(SecretBuffer(kTestData), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  {
    SecretData c(kTestData, absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  {
    SecretData c(
        absl::MakeSpan(reinterpret_cast<const uint8_t*>(kTestData.data()),
                       kTestData.size()),
        absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), Not(IsOk()));
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(1)));
  }
  // Empty buffer ignores the CRC32C parameter and always returns 0.
  {
    SecretData c(SecretBuffer(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretData c(absl::string_view(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
  {
    SecretData c(absl::Span<const uint8_t>(), absl::crc32c_t(1));
    EXPECT_THAT(c.ValidateCrc32c(), IsOk());
    EXPECT_THAT(c.GetCrc32c(), Eq(absl::crc32c_t(0)));
  }
}

TEST(SecretDataTest, SecretDataFromSpan) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data = util::SecretDataFromSpan(kContents);
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, SecretDataFromStringViewConstructor) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = util::SecretDataFromStringView(s);
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, StringViewFromSecretData) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = util::SecretDataFromStringView(s);
  absl::string_view data_view = util::SecretDataAsStringView(data);
  EXPECT_THAT(data_view, Eq(s));
}

TEST(SecretDataTest, SecretDataCopy) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data = util::SecretDataFromSpan(kContents);
  SecretData data_copy = data;
  EXPECT_THAT(data_copy, ElementsAreArray(kContents));
}

TEST(SecretDataTest, SecretDataEqualsTrue) {
  SecretData d1 = util::SecretDataFromStringView("abc");
  SecretData d2 = util::SecretDataFromStringView("abc");
  EXPECT_THAT(util::SecretDataEquals(d1, d2), Eq(true));
}

TEST(SecretDataTest, SecretDataEqualsFalse) {
  SecretData d1 = util::SecretDataFromStringView("abc");
  SecretData d2 = util::SecretDataFromStringView("1234");
  EXPECT_THAT(util::SecretDataEquals(d1, d2), Eq(false));
}

TEST(SecretDataTest, SecretDataEqualsFalseSize) {
  SecretData d1 = util::SecretDataFromStringView("abc");
  SecretData d2 = util::SecretDataFromStringView("ab");
  EXPECT_THAT(util::SecretDataEquals(d1, d2), Eq(false));
}

TEST(SecretDataTest, UtilInternalAsSecretBuffer) {
  SecretData data = util::SecretDataFromStringView("abc");
  SecretBuffer buffer = util::internal::AsSecretBuffer(data);
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, ToSecretBufferRvalue) {
  SecretData data = util::SecretDataFromStringView("abc");
  SecretBuffer buffer = util::internal::AsSecretBuffer(std::move(data));
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, UtilInternalAsSecretData) {
  SecretBuffer buffer = SecretBuffer("abc");
  SecretData data = util::internal::AsSecretData(buffer);
  EXPECT_THAT(util::SecretDataAsStringView(data), Eq("abc"));
}

TEST(SecretDataTest, FromSecretBufferRvalue) {
  SecretBuffer buffer = SecretBuffer("abc");
  SecretData data = util::internal::AsSecretData(std::move(buffer));
  EXPECT_THAT(util::SecretDataAsStringView(data), Eq("abc"));
}

void BM_SecretDataFromSecretBuffer(benchmark::State& state) {
  for (auto s : state) {
    state.PauseTiming();
    SecretBuffer data(state.range(0), 'x');
    benchmark::DoNotOptimize(data);
    state.ResumeTiming();
    SecretData secret_data = util::internal::AsSecretData(std::move(data));
    benchmark::DoNotOptimize(secret_data);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_SecretDataFromSecretBufferCopy(benchmark::State& state) {
  SecretBuffer data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    SecretData secret_data = util::internal::AsSecretData(data);
    benchmark::DoNotOptimize(secret_data);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_SecretDataFromStringView(benchmark::State& state) {
  std::string data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    SecretData secret_data = util::SecretDataFromStringView(data);
    benchmark::DoNotOptimize(secret_data);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

BENCHMARK(BM_SecretDataFromSecretBuffer)
    ->Arg(1)
    ->Arg(32)
    ->Arg(2048)
    ->Arg(1 << 10)
    ->Arg(1 << 20);

BENCHMARK(BM_SecretDataFromSecretBufferCopy)
    ->Arg(1)
    ->Arg(32)
    ->Arg(2048)
    ->Arg(1 << 10)
    ->Arg(1 << 20);

BENCHMARK(BM_SecretDataFromStringView)
    ->Arg(1)
    ->Arg(32)
    ->Arg(2048)
    ->Arg(1 << 10)
    ->Arg(1 << 20);

}  // namespace
}  // namespace tink
}  // namespace crypto
