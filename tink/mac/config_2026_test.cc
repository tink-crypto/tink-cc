// Copyright 2023 Google LLC
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

#include "tink/mac/config_2026.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/chunked_mac.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/key_gen_config_2026.h"
#include "tink/mac/mac_key_templates.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

using Config2026Test = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(Config2026TestSuite, Config2026Test,
                         Values(MacKeyTemplates::AesCmac(),
                                MacKeyTemplates::HmacSha256()));

TEST_P(Config2026Test, GetPrimitive) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigMac2026());
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<Mac>> mac =
      (*handle)->GetPrimitive<Mac>(ConfigMac2026());
  ASSERT_THAT(mac, IsOk());

  std::string data = "data";
  absl::StatusOr<std::string> tag = (*mac)->ComputeMac(data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT((*mac)->VerifyMac(*tag, data), IsOk());
}

TEST_P(Config2026Test, GetPrimitiveChunkedMac) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigMac2026());
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*handle)->GetPrimitive<ChunkedMac>(ConfigMac2026());
  ASSERT_THAT(chunked_mac, IsOk());

  std::string data1 = "da";
  std::string data2 = "ta";

  absl::StatusOr<std::unique_ptr<ChunkedMacComputation>> compute =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(compute, IsOk());
  ASSERT_THAT((*compute)->Update(data1), IsOk());
  ASSERT_THAT((*compute)->Update(data2), IsOk());
  absl::StatusOr<std::string> tag = (*compute)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  absl::StatusOr<std::unique_ptr<ChunkedMacVerification>> verify =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verify, IsOk());
  ASSERT_THAT((*verify)->Update(data1), IsOk());
  ASSERT_THAT((*verify)->Update(data2), IsOk());
  EXPECT_THAT((*verify)->VerifyMac(), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
