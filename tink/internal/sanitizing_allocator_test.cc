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

#include "tink/internal/sanitizing_allocator.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace util {
namespace internal {

namespace {

using ::testing::ElementsAre;

TEST(SanitizingAllocatorTest, Basic) {
  std::vector<char, SanitizingAllocator<char>> vector;
  vector.push_back('a');
  vector.push_back('b');
  vector.push_back('c');
  EXPECT_THAT(vector, ElementsAre('a', 'b', 'c'));
}

TEST(SanitizingAllocatorTest, Equality) {
  SanitizingAllocator<char> allocator1;
  SanitizingAllocator<char> allocator2;
  EXPECT_TRUE(allocator1 == allocator2);
  EXPECT_FALSE(allocator1 != allocator2);
}

}  // namespace

}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto
