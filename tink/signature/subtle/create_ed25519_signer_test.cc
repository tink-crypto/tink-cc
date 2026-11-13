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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/subtle/create_ed25519_signer.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::internal::CreateEd25519TestVectors;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateEd25519PublicKeySignTestVectorTest
    : public TestWithParam<SignatureTestVector> {};

TEST_P(CreateEd25519PublicKeySignTestVectorTest, SignTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  const Ed25519PrivateKey& private_key = dynamic_cast<const Ed25519PrivateKey&>(
      *test_vector.signature_private_key);
  if (internal::IsFipsModeEnabled()) {
    EXPECT_THAT(CreateEd25519PublicKeySign(private_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateEd25519PublicKeySign(private_key);
  ASSERT_THAT(signer, IsOk());

  EXPECT_THAT((*signer)->Sign(test_vector.message),
              IsOkAndHolds(test_vector.signature));
}

INSTANTIATE_TEST_SUITE_P(CreateEd25519PublicKeySignTestVectorTests,
                         CreateEd25519PublicKeySignTestVectorTest,
                         ValuesIn(CreateEd25519TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
