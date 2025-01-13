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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using testing::Eq;

TEST(SecretBufferTest, ResizeAndSize) {
  SecretBuffer buffer;
  EXPECT_THAT(buffer.size(), Eq(0));
  buffer.resize(10);
  EXPECT_THAT(buffer.size(), Eq(10));
}

TEST(SecretBufferTest, ReadAndWrite) {
  SecretBuffer buffer;
  buffer.resize(100);
  for (int i = 0; i < 100; ++i) {
    buffer[i] = static_cast<uint8_t>((11 * i + 17) % 256);
  }
  for (int i = 0; i < 100; ++i) {
    EXPECT_THAT(buffer[i], Eq(static_cast<uint8_t>((11 * i + 17) % 256)));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
