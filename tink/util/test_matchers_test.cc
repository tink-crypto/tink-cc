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
#include "tink/util/test_matchers.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace test {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::Not;

TEST(TestMatchersTest, MatchersWithStatusOr) {
  absl::StatusOr<int> status_or_with_value = 123;
  EXPECT_THAT(status_or_with_value, IsOkAndHolds(Eq(123)));
  EXPECT_THAT(status_or_with_value, Not(IsOkAndHolds(Eq(124))));
  EXPECT_THAT(status_or_with_value, IsOk());
  EXPECT_THAT(status_or_with_value, StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(status_or_with_value,
              Not(StatusIs(absl::StatusCode::kInvalidArgument)));

  absl::StatusOr<int> invalid_status_or =
      absl::Status(absl::StatusCode::kInvalidArgument, "invalid argument");
  EXPECT_THAT(invalid_status_or, Not(IsOkAndHolds(Eq(123))));
  EXPECT_THAT(invalid_status_or, Not(IsOk()));
  EXPECT_THAT(invalid_status_or, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(invalid_status_or, Not(StatusIs(absl::StatusCode::kOk)));
}

TEST(TestMatchersTest, MatchersWithStatus) {
  absl::Status ok_status = absl::OkStatus();
  EXPECT_THAT(ok_status, IsOk());
  EXPECT_THAT(ok_status, StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(ok_status, Not(StatusIs(absl::StatusCode::kInvalidArgument)));

  absl::Status invalid_arg =
      absl::Status(absl::StatusCode::kInvalidArgument, "invalid argument");
  EXPECT_THAT(invalid_arg, Not(IsOk()));
  EXPECT_THAT(invalid_arg, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(invalid_arg, Not(StatusIs(absl::StatusCode::kOk)));
}

}  // namespace
}  // namespace internal
}  // namespace test
}  // namespace tink
}  // namespace crypto
