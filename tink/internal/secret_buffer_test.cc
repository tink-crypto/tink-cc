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
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/util/secret_data.h"
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

TEST(SecretBufferTest, Empty) {
  SecretBuffer buffer;
  EXPECT_THAT(buffer.empty(), Eq(true));
  buffer.resize(10);
  EXPECT_THAT(buffer.empty(), Eq(false));
}

TEST(SecretBufferTest, Clear) {
  SecretBuffer buffer("some data");
  EXPECT_THAT(buffer.empty(), IsFalse());
  buffer.clear();
  EXPECT_THAT(buffer.empty(), IsTrue());
  EXPECT_THAT(buffer.capacity(), Eq(0));
  EXPECT_THAT(buffer.size(), Eq(0));
}

TEST(SecretBufferTest, Capacity) {
  absl::string_view data = "some data";
  SecretBuffer buffer(data);
  EXPECT_THAT(buffer.capacity(), Eq(data.size()));
  buffer.resize(100);
  EXPECT_THAT(buffer.capacity(), Eq(100));

  SecretBuffer buffer2;
  buffer2.reserve(100);
  EXPECT_THAT(buffer2.capacity(), Eq(100));
}

TEST(SecretBufferTest, ConstructorWithSizeAndVal) {
  SecretBuffer buffer(100, 0x99);
  EXPECT_THAT(buffer.size(), Eq(100));
  for (int i = 0; i < buffer.size(); ++i) {
    EXPECT_THAT(buffer[i], Eq(0x99)) << i;
  }
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

TEST(SecretBufferTest, SpanConstructor) {
  std::string data = "Some data to construct a secret buffer";
  SecretBuffer buffer(absl::Span<const uint8_t>(
      reinterpret_cast<uint8_t*>(data.data()), data.size()));
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

TEST(SecretBufferTest, CopyConstructor) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2(buffer1);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data")));
  EXPECT_THAT(buffer2, Eq(SecretBuffer("some data")));
}

TEST(SecretBufferTest, CopyAssignment) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2;
  buffer2 = buffer1;
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data")));
  EXPECT_THAT(buffer2, Eq(SecretBuffer("some data")));
}

TEST(SecretBufferTest, MoveConstructor) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2(std::move(buffer1));
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(buffer1.size(), Eq(0));
  EXPECT_THAT(buffer2, Eq(SecretBuffer("some data")));
}

TEST(SecretBufferTest, MoveAssignment) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2;
  buffer2 = std::move(buffer1);
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_THAT(buffer1.size(), Eq(0));
  EXPECT_THAT(buffer2, Eq(SecretBuffer("some data")));
}

TEST(SecretBufferTest, Swap) {
  SecretBuffer buffer1("some data1");
  SecretBuffer buffer2("some data2");
  buffer1.swap(buffer2);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data2")));
  EXPECT_THAT(buffer2.AsStringView(), Eq("some data1"));
}

TEST(SecretBufferTest, SwapWithEmpty) {
  SecretBuffer buffer1("some data");
  SecretBuffer buffer2;
  buffer1.swap(buffer2);
  EXPECT_THAT(buffer1.AsStringView(), Eq(""));
  EXPECT_THAT(buffer2.AsStringView(), Eq("some data"));
  buffer1.swap(buffer2);
  EXPECT_THAT(buffer1.AsStringView(), Eq("some data"));
  EXPECT_THAT(buffer2.AsStringView(), Eq(""));
}

TEST(SecretBufferTest, Append) {
  SecretBuffer buffer1("some data;");
  SecretBuffer buffer2("some other data;");
  buffer1.append(buffer2);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;some other data;")));
}

TEST(SecretBufferTest, AppendWithEmpty) {
  SecretBuffer buffer1("some data;");
  SecretBuffer buffer2;
  buffer1.append(buffer2);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;")));
}

TEST(SecretBufferTest, AppendWithEmpty2) {
  SecretBuffer buffer1;
  SecretBuffer buffer2("some data;");
  buffer1.append(buffer2);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;")));
}

TEST(SecretBufferTest, AppendStringView) {
  SecretBuffer buffer1("some data;");
  SecretBuffer buffer2("some other data;");
  buffer1.append(buffer2.AsStringView());
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;some other data;")));
}

TEST(SecretBufferTest, AppendStringViewWithEmpty) {
  SecretBuffer buffer1("some data;");
  SecretBuffer buffer2;
  buffer1.append(buffer2.AsStringView());
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;")));
}

TEST(SecretBufferTest, AppendStringViewWithEmpty2) {
  SecretBuffer buffer1;
  SecretBuffer buffer2("some data;");
  buffer1.append(buffer2.AsStringView());
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;")));
}

TEST(SecretBufferTest, AppendWithSecretData) {
  SecretBuffer buffer1("some data;");
  SecretData data = util::SecretDataFromStringView("some other data;");
  buffer1.append(data);
  EXPECT_THAT(buffer1, Eq(SecretBuffer("some data;some other data;")));
}

TEST(SecretBufferTest, SubstrConstRef) {
  constexpr absl::string_view kData = "Some arbitrary data";
  SecretBuffer buffer(kData);
  for (int start = 0; start <= kData.size(); ++start) {
    for (int num = 0; num <= kData.size(); ++num) {
      EXPECT_THAT(buffer.substr(start, num),
                  Eq(SecretBuffer(kData.substr(start, num))))
          << "substr(" << start << ", " << num << ")";
    }
  }
}

TEST(SecretBufferTest, SubstrRvalueRef) {
  constexpr absl::string_view kData = "Some arbitrary data";
  SecretBuffer buffer(kData);
  for (int start = 0; start <= kData.size(); ++start) {
    for (int num = 0; num <= kData.size(); ++num) {
      SecretBuffer tmp_buffer = buffer;
      EXPECT_THAT(std::move(tmp_buffer).substr(start, num),
                  Eq(SecretBuffer(kData.substr(start, num))))
          << "substr(" << start << ", " << num << ")";
    }
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
