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

#include "tink/signature/internal/ed25519_sign_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::NotNull;

TEST(Ed25519SignBoringSslTest, SignEmptyAndNullStringView) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const SignatureTestVector& test_vector =
      CreateEd25519EmptyMessageTestVector();
  const Ed25519PrivateKey* typed_key = dynamic_cast<const Ed25519PrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewEd25519SignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());

  const absl::string_view kNullStringView;
  EXPECT_THAT((*signer)->Sign(kNullStringView),
              IsOkAndHolds(test_vector.signature));
  EXPECT_THAT((*signer)->Sign(""), IsOkAndHolds(test_vector.signature));
  EXPECT_THAT((*signer)->Sign(absl::string_view()),
              IsOkAndHolds(test_vector.signature));
}

using Ed25519SignBoringSslTestVectorTest =
    testing::TestWithParam<SignatureTestVector>;

TEST_P(Ed25519SignBoringSslTestVectorTest, SignTestVectors) {
  const SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (IsFipsModeEnabled()) {
    EXPECT_THAT(NewEd25519SignBoringSsl(*typed_key),
                StatusIs(absl::StatusCode::kInternal));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewEd25519SignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());
  EXPECT_THAT((*signer)->Sign(param.message), IsOkAndHolds(param.signature));
}

INSTANTIATE_TEST_SUITE_P(Ed25519SignBoringSslTestVectorTests,
                         Ed25519SignBoringSslTestVectorTest,
                         testing::ValuesIn(CreateEd25519TestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
