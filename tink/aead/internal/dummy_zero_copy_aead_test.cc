// Copyright 2026 Google LLC
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

#include "tink/aead/internal/dummy_zero_copy_aead.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/types/span.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;

TEST(DummyZeroCopyAeadTest, Encrypt) {
  DummyZeroCopyAead aead("dummy");
  std::string buffer(aead.MaxEncryptionSize(3), '\0');
  absl::StatusOr<int64_t> size =
      aead.Encrypt("foo", "bar", absl::MakeSpan(buffer));
  ASSERT_THAT(size, IsOk());
  buffer.resize(*size);
  EXPECT_THAT(buffer, Eq("5:3:dummybarfoo"));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
