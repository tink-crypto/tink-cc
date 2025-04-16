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

#include "tink/internal/endian.h"

#include <sys/types.h>

#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::ElementsAre;

TEST(EndianTest, LoadBigEndian32) {
  {
    uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_EQ(LoadBigEndian32(data), 0x01020304);
  }
  {
    uint8_t data[7] = {0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    EXPECT_EQ(LoadBigEndian32(data + 2), 0x01020304);
  }
}

TEST(EndianTest, StoreBigEndian32) {
  uint32_t value = 0x01020304;
  {
    uint8_t data[4];
    StoreBigEndian32(data, value);
    EXPECT_THAT(data, ElementsAre(0x01, 0x02, 0x03, 0x04));
  }
  {
    uint8_t data[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    StoreBigEndian32(data + 3, value);
    EXPECT_THAT(data, ElementsAre(0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
