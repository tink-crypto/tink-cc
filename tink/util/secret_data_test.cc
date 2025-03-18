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

#include "tink/util/secret_data.h"

#include <cstddef>
#include <string>
#include <type_traits>
#include <utility>

#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/internal/secret_buffer.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::crypto::tink::internal::SecretBuffer;
using ::testing::AnyOf;
using ::testing::ElementsAreArray;
using ::testing::Eq;

constexpr int kEightKb = 8192;
struct alignas(kEightKb) TwoMbAlignedStruct {
  int data;
};

// If we don't have __cpp_aligned_new we currently do not support types
// whose alginment requirement is greater than the default.
#ifdef __cpp_aligned_new

TEST(SecretUniqueptrTest, Alignment) {
  SecretUniquePtr<TwoMbAlignedStruct> s =
      MakeSecretUniquePtr<TwoMbAlignedStruct>();
  EXPECT_THAT(reinterpret_cast<size_t>(s.get()) % kEightKb, Eq(0));
}

#endif

TEST(SecretDataTest, SecretDataFromSpan) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data = SecretDataFromSpan(kContents);
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, SecretDataFromStringViewConstructor) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = SecretDataFromStringView(s);
  EXPECT_THAT(data, ElementsAreArray(kContents));
}

TEST(SecretDataTest, StringViewFromSecretData) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 124, 16};
  std::string s;
  for (unsigned char c : kContents) {
    s.push_back(c);
  }
  SecretData data = SecretDataFromStringView(s);
  absl::string_view data_view = SecretDataAsStringView(data);
  EXPECT_THAT(data_view, Eq(s));
}

TEST(SecretDataTest, SecretDataCopy) {
  constexpr unsigned char kContents[] = {41, 42, 64, 12, 41,  0,
                                         52, 56, 6,  12, 127, 13};
  SecretData data = SecretDataFromSpan(kContents);
  SecretData data_copy = data;
  EXPECT_THAT(data_copy, ElementsAreArray(kContents));
}

TEST(SecretDataTest, SecretDataEqualsTrue) {
  SecretData d1 = SecretDataFromStringView("abc");
  SecretData d2 = SecretDataFromStringView("abc");
  EXPECT_THAT(SecretDataEquals(d1, d2), Eq(true));
}

TEST(SecretDataTest, SecretDataEqualsFalse) {
  SecretData d1 = SecretDataFromStringView("abc");
  SecretData d2 = SecretDataFromStringView("1234");
  EXPECT_THAT(SecretDataEquals(d1, d2), Eq(false));
}

TEST(SecretDataTest, SecretDataEqualsFalseSize) {
  SecretData d1 = SecretDataFromStringView("abc");
  SecretData d2 = SecretDataFromStringView("ab");
  EXPECT_THAT(SecretDataEquals(d1, d2), Eq(false));
}

TEST(SecretDataTest, ToSecretBuffer) {
  SecretData data = SecretDataFromStringView("abc");
  SecretBuffer buffer = internal::AsSecretBuffer(data);
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, ToSecretBufferRvalue) {
  SecretData data = SecretDataFromStringView("abc");
  SecretBuffer buffer = internal::AsSecretBuffer(std::move(data));
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, FromSecretBuffer) {
  SecretBuffer buffer = SecretBuffer("abc");
  SecretData data = internal::AsSecretData(buffer);
  EXPECT_THAT(SecretDataAsStringView(data), Eq("abc"));
}

TEST(SecretDataTest, FromSecretBufferRvalue) {
  SecretBuffer buffer = SecretBuffer("abc");
  SecretData data = internal::AsSecretData(std::move(buffer));
  EXPECT_THAT(SecretDataAsStringView(data), Eq("abc"));
}

struct MyNonTrivialInt {
  explicit MyNonTrivialInt(int value = 0) : value(value) {}
  MyNonTrivialInt(const MyNonTrivialInt& other) { value = other.value; }
  MyNonTrivialInt& operator=(const MyNonTrivialInt& other) = default;
  bool operator==(const MyNonTrivialInt& other) const {
    return value == other.value;
  }
  bool operator!=(const MyNonTrivialInt& other) const {
    return value != other.value;
  }
  int value;
};

static_assert(!std::is_trivially_copyable_v<MyNonTrivialInt>);

template <typename T>
class SecretValueTest : public testing::Test {};

using TestTypes = ::testing::Types<int, MyNonTrivialInt>;
TYPED_TEST_SUITE(SecretValueTest, TestTypes);

TYPED_TEST(SecretValueTest, DefaultConstructor) {
  SecretValue<TypeParam> s;
  EXPECT_THAT(s.value(), Eq(TypeParam(0)));
}

TYPED_TEST(SecretValueTest, Constructor) {
  SecretValue<TypeParam> s(TypeParam(102));
  EXPECT_THAT(s.value(), Eq(TypeParam(102)));
}

TYPED_TEST(SecretValueTest, CopyConstructor) {
  SecretValue<TypeParam> s(TypeParam(102));
  SecretValue<TypeParam> t(s);
  EXPECT_THAT(t.value(), Eq(TypeParam(102)));
}

TYPED_TEST(SecretValueTest, AssignmentOperator) {
  SecretValue<TypeParam> s(TypeParam(102));
  SecretValue<TypeParam> t(TypeParam(101));
  t = s;
  EXPECT_THAT(t.value(), Eq(TypeParam(102)));
}

TYPED_TEST(SecretValueTest, MoveConstructor) {
  SecretValue<TypeParam> s(TypeParam(102));
  SecretValue<TypeParam> t(std::move(s));
  EXPECT_THAT(t.value(), Eq(TypeParam(102)));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(s.value(), AnyOf(Eq(TypeParam(0)), Eq(TypeParam(102))));
}

TYPED_TEST(SecretValueTest, MoveAssignment) {
  SecretValue<TypeParam> s(TypeParam(102));
  SecretValue<TypeParam> t;
  t = std::move(s);
  EXPECT_THAT(t.value(), Eq(TypeParam(102)));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(s.value(), AnyOf(Eq(TypeParam(0)), Eq(TypeParam(102))));
}

void BM_SecretDataFromSecretBuffer(benchmark::State& state) {
  for (auto s : state) {
    state.PauseTiming();
    SecretBuffer data(state.range(0), 'x');
    benchmark::DoNotOptimize(data);
    state.ResumeTiming();
    SecretData secret_data = internal::AsSecretData(std::move(data));
    benchmark::DoNotOptimize(secret_data);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_SecretDataFromSecretBufferCopy(benchmark::State& state) {
  SecretBuffer data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    SecretData secret_data = internal::AsSecretData(data);
    benchmark::DoNotOptimize(secret_data);
  }
  state.SetBytesProcessed(state.iterations() * state.range(0));
}

void BM_SecretDataFromStringView(benchmark::State& state) {
  std::string data(state.range(0), 'x');
  benchmark::DoNotOptimize(data);
  for (auto s : state) {
    SecretData secret_data = SecretDataFromStringView(data);
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
}  // namespace util
}  // namespace tink
}  // namespace crypto
