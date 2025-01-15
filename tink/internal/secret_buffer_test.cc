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

#include "tink/internal/secret_buffer.h"
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using testing::Eq;
using testing::IsFalse;
using testing::IsTrue;

TEST(SecretBufferTest, ResizeAndSize) {
  SecretBuffer buffer;
  EXPECT_THAT(buffer.size(), Eq(0));
  buffer.resize(10);
  EXPECT_THAT(buffer.size(), Eq(10));
}

TEST(SecretBufferTest, WriteAndReadWithAllMethods) {
  SecretBuffer buffer;
  buffer.resize(100);
  for (int i = 0; i < 100; ++i) {
    buffer[i] = static_cast<uint8_t>((11 * i + 17) % 256);
  }
  for (int i = 0; i < 100; ++i) {
    EXPECT_THAT(buffer[i], Eq(static_cast<uint8_t>((11 * i + 17) % 256)));
    EXPECT_THAT(*(buffer.data() + i),
                Eq(static_cast<uint8_t>((11 * i + 17) % 256)));
  }
}

TEST(SecretBufferTest, WriteWithData) {
  SecretBuffer buffer;
  buffer.resize(100);
  for (int i = 0; i < 100; ++i) {
    *(buffer.data() + i) = static_cast<uint8_t>((11 * i + 17) % 256);
  }
  for (int i = 0; i < 100; ++i) {
    EXPECT_THAT(buffer[i], Eq(static_cast<uint8_t>((11 * i + 17) % 256)));
  }
}

TEST(SecretBufferTest, StringViewAccessor) {
  SecretBuffer buffer;
  buffer.resize(30);
  for (int i = 0; i < 30; ++i) {
    *(buffer.data() + i) = static_cast<uint8_t>((11 * i + 17) % 256);
  }
  EXPECT_THAT(
      test::HexEncode(buffer.AsStringView()),
      Eq("111c27323d48535e69747f8a95a0abb6c1ccd7e2edf8030e19242f3a4550"));
}

TEST(SecretBufferTest, StringViewConstructor) {
  std::string data = "Some data to construct a secret buffer";
  SecretBuffer buffer(data);
  EXPECT_THAT(buffer.size(), Eq(data.size()));
  EXPECT_THAT(buffer.AsStringView(), Eq(data));
}

TEST(SecretBufferTest, EqualityForEqualObjects) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2("some data");
  EXPECT_THAT(buffer1 == buffer2, IsTrue());
  EXPECT_THAT(buffer1 != buffer2, IsFalse());
}

TEST(SecretBufferTest, EqualityForNonEqualObjects) {
  SecretBuffer buffer1("some data1");
  SecretBuffer buffer2("some data2");
  SecretBuffer buffer3("s");
  EXPECT_THAT(buffer1 == buffer2, IsFalse());
  EXPECT_THAT(buffer1 == buffer3, IsFalse());
  EXPECT_THAT(buffer1 != buffer2, IsTrue());
  EXPECT_THAT(buffer1 != buffer3, IsTrue());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
