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
#include "tink/aead/internal/aead_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::ResultOf;

TEST(AeadUtilTest, GetAesGcmCipherForKeySize) {
  for (int i = 0; i < 64; i++) {
    absl::StatusOr<const EVP_CIPHER *> cipher = GetAesGcmCipherForKeySize(i);
    if (i == 16) {
      EXPECT_THAT(cipher,
                  IsOkAndHolds(ResultOf(EVP_CIPHER_nid, NID_aes_128_gcm)));
    } else if (i == 32) {
      EXPECT_THAT(cipher,
                  IsOkAndHolds(ResultOf(EVP_CIPHER_nid, NID_aes_256_gcm)));
    } else {
      EXPECT_THAT(cipher, Not(IsOk()));
    }
  }
}

TEST(AeadUtilTest, SupportedKmsEnvelopeAeadDekKeyTypes) {
  EXPECT_THAT(IsSupportedKmsEnvelopeAeadDekKeyType(
                  "type.googleapis.com/google.crypto.tink.AesGcmKey"),
              IsTrue());
  EXPECT_THAT(IsSupportedKmsEnvelopeAeadDekKeyType(
                  "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey"),
              IsFalse());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
