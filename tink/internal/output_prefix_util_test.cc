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
////////////////////////////////////////////////////////////////////////////////

#include "tink/internal/output_prefix_util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;

TEST(OutputPrefixUtil, ComputeOutputPrefix) {
  EXPECT_THAT(ComputeOutputPrefix(0, 1),
              Eq(std::string("\x00\x00\x00\x00\x01", 5)));
  EXPECT_THAT(ComputeOutputPrefix(1, 1),
              Eq(std::string("\x01\x00\x00\x00\x01", 5)));
  EXPECT_THAT(ComputeOutputPrefix(0, 0x01020304),
              Eq(std::string("\x00\x01\x02\x03\x04", 5)));
  EXPECT_THAT(ComputeOutputPrefix(1, 0x01020304),
              Eq(std::string("\x01\x01\x02\x03\x04", 5)));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
