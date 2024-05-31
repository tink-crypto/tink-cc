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

#include "tink/aead/internal/cord_utils.h"

#include <cstring>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_test_helpers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::IsEmpty;
using ::testing::SizeIs;

constexpr absl::string_view kData = "This is a test string.";

TEST(CordUtilsTest, CordWriterWrite) {
  std::string expected_string = subtle::Random::GetRandomBytes(1 << 20);
  CordWriter writer(expected_string.size());
  for (absl::string_view chunk :
       absl::StrSplit(expected_string, absl::ByLength(1 << 10))) {
    writer.Write(chunk);
  }
  EXPECT_EQ(std::move(writer).data(), expected_string);
}

TEST(CordUtilsTest, CordWriterWriteUsingNextWriteBufferAndAdvance) {
  std::string expected_string = subtle::Random::GetRandomBytes(1 << 20);
  CordWriter writer(expected_string.size());
  for (absl::string_view chunk :
       absl::StrSplit(expected_string, absl::ByLength(1 << 10))) {
    while (!chunk.empty()) {
      absl::Span<char> to_write =
          writer.NextWriteBuffer().subspan(0, chunk.size());
      std::memcpy(to_write.data(), chunk.data(), to_write.size());
      writer.Advance(to_write.size());
      chunk.remove_prefix(to_write.size());
    }
  }
  EXPECT_EQ(std::move(writer).data(), expected_string);
}

TEST(CordUtilsTest, CordWriterNextWriteBufferReturnsEmptySpanAfterMaxSize) {
  constexpr int kMaxSize = 100;
  CordWriter writer(kMaxSize);
  absl::Span<char> buffer = writer.NextWriteBuffer();
  ASSERT_THAT(buffer, SizeIs(kMaxSize));
  writer.Advance(buffer.size());
  // Next buffer should be empty.
  EXPECT_THAT(writer.NextWriteBuffer(), IsEmpty());
}

TEST(CordUtilsDeathTest, CordWriterWriteDiesIfWritingMoreThanMaxSize) {
  constexpr int kMaxSize = 100;
  CordWriter writer(kMaxSize);
  EXPECT_DEATH(writer.Write(std::string(kMaxSize + 1, 'a')), "");
}

TEST(CordUtilsDeathTest, CordWriterWriteDiesIfAdvancingMoreThanCurrentBuffer) {
  constexpr int kMaxSize = 100;
  CordWriter writer(kMaxSize);
  absl::Span<char> buffer = writer.NextWriteBuffer();
  ASSERT_THAT(buffer, SizeIs(kMaxSize));
  EXPECT_DEATH(writer.Advance(buffer.size() + 1), "");
}

TEST(CordUtilsTest, CordReaderReadAllWithPeekAndSkip) {
  absl::Cord fragmented_cord = absl::MakeFragmentedCord(absl::StrSplit(
      subtle::Random::GetRandomBytes(1 << 20), absl::ByLength(1 << 10)));
  CordReader reader(fragmented_cord);
  absl::Cord read_data;
  while (reader.Available() > 0) {
    absl::string_view chunk = reader.Peek();
    read_data.Append(chunk);
    reader.Skip(chunk.size());
  }
  EXPECT_EQ(read_data, fragmented_cord.Flatten());
  EXPECT_THAT(reader.Peek(), IsEmpty());
}

TEST(CordUtilsTest, CordReaderReadAllWithReadN) {
  absl::Cord fragmented_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kData, absl::ByLength(3)));
  CordReader reader(fragmented_cord);
  std::string read_data(kData.size(), '\0');
  reader.ReadN(kData.size(), &read_data[0]);
  EXPECT_EQ(read_data, kData);
  EXPECT_EQ(reader.Available(), 0);
}

TEST(CordUtilsTest, CordReaderReadAllWithMultipleReadN) {
  absl::Cord fragmented_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kData, absl::ByLength(3)));
  CordReader reader(fragmented_cord);

  for (absl::string_view chunk : absl::StrSplit(kData, absl::ByLength(5))) {
    std::string read_data(chunk.size(), '\0');
    reader.ReadN(chunk.size(), &read_data[0]);
    EXPECT_EQ(read_data, chunk);
  }
  EXPECT_EQ(reader.Available(), 0);
}

TEST(CordUtilsTest, CordReaderSkipToArbitraryPosition) {
  absl::Cord fragmented_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kData, absl::ByLength(3)));
  CordReader reader(fragmented_cord);
  reader.Skip(10);
  EXPECT_EQ(reader.Available(), kData.size() - 10);
}

TEST(CordUtilsTest, CordReaderPeekWithoutSkipAlwaysReturnsSameStringView) {
  absl::Cord fragmented_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kData, absl::ByLength(3)));
  CordReader reader(fragmented_cord);
  absl::string_view chunk = reader.Peek();
  EXPECT_EQ(reader.Peek(), chunk);
  EXPECT_EQ(reader.Peek(), chunk);
}

TEST(CordUtilsDeathTest, CordReaderReadNDiesIfReadingMoreThanAvailable) {
  absl::Cord fragmented_cord =
      absl::MakeFragmentedCord(absl::StrSplit(kData, absl::ByLength(3)));
  CordReader reader(fragmented_cord);
  EXPECT_DEATH(reader.ReadN(kData.size() + 1, /*dest=*/nullptr), "");
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
