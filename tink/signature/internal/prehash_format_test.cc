// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/prehash_format.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::testing::Eq;

TEST(PrehashFormatTest, Constants) {
  EXPECT_THAT(kPrehashStartByte, Eq(0xff));
  EXPECT_THAT(kPrehashPrefixSize, Eq(5));
}

TEST(PrehashFormatTest, GetPrehashPrefix) {
  EXPECT_THAT(GetPrehashPrefix(0x00000000), Eq(HexDecodeOrDie("ff00000000")));
  EXPECT_THAT(GetPrehashPrefix(0x12345678), Eq(HexDecodeOrDie("ff12345678")));
  EXPECT_THAT(GetPrehashPrefix(0xffffffff), Eq(HexDecodeOrDie("ffffffffff")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
