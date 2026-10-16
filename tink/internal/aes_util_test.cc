// Copyright 2021 Google LLC
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
#include "tink/internal/aes_util.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::Not;

TEST(AesUtilTest, GetAesCtrCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_CIPHER *> cipher = GetAesCtrCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_128_ctr()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_256_ctr()));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

TEST(AesUtilTest, GetAesCbcCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_CIPHER *> cipher = GetAesCbcCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_128_cbc()));
    } else if (i == 32) {
      EXPECT_THAT(cipher, IsOkAndHolds(EVP_aes_256_cbc()));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
