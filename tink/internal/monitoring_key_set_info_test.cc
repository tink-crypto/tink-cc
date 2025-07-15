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
#include "tink/internal/monitoring_key_set_info.h"

#include "gtest/gtest.h"
#include "tink/key_status.h"

namespace crypto::tink::internal {

bool operator==(
    const crypto::tink::internal::MonitoringKeySetInfo::Entry& lhs,
    const crypto::tink::internal::MonitoringKeySetInfo::Entry& rhs) {
  return lhs.GetStatus() == rhs.GetStatus() &&
         lhs.GetKeyId() == rhs.GetKeyId() &&
         lhs.GetKeyType() == rhs.GetKeyType() &&
         lhs.GetKeyPrefix() == rhs.GetKeyPrefix();
}

bool operator!=(
    const crypto::tink::internal::MonitoringKeySetInfo::Entry& lhs,
    const crypto::tink::internal::MonitoringKeySetInfo::Entry& rhs) {
  return !(lhs == rhs);
}

namespace {

TEST(MonitoringKeySetInfoTest, CanCopyAndAssign) {
  MonitoringKeySetInfo info(
      {{"key1", "value1"}, {"key2", "value2"}},
      {MonitoringKeySetInfo::Entry(KeyStatus::kEnabled, 1, "type1", "prefix1"),
       MonitoringKeySetInfo::Entry(KeyStatus::kDisabled, 2, "type2",
                                   "prefix2")},
      1);
  MonitoringKeySetInfo info_assigned({}, {}, 0);

  MonitoringKeySetInfo info_copy = info;
  info_assigned = info;

  EXPECT_EQ(info.GetAnnotations(), info_copy.GetAnnotations());
  EXPECT_EQ(info.GetEntries(), info_copy.GetEntries());
  EXPECT_EQ(info.GetPrimaryKeyId(), info_copy.GetPrimaryKeyId());
  EXPECT_EQ(info_assigned.GetAnnotations(), info.GetAnnotations());
  EXPECT_EQ(info_assigned.GetEntries(), info.GetEntries());
  EXPECT_EQ(info_assigned.GetPrimaryKeyId(), info.GetPrimaryKeyId());
}

}  // namespace
}  // namespace crypto::tink::internal
