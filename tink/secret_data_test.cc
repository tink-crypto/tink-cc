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

#include <string>
#include <utility>

#include "benchmark/benchmark.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::SecretBuffer;
using ::testing::ElementsAreArray;
using ::testing::Eq;

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

TEST(SecretDataTest, ToSecretBuffer) {
  SecretData data = util::SecretDataFromStringView("abc");
  SecretBuffer buffer = util::internal::AsSecretBuffer(data);
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, ToSecretBufferRvalue) {
  SecretData data = util::SecretDataFromStringView("abc");
  SecretBuffer buffer = util::internal::AsSecretBuffer(std::move(data));
  EXPECT_THAT(buffer.AsStringView(), Eq("abc"));
}

TEST(SecretDataTest, FromSecretBuffer) {
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
