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

#include "tink/signature/internal/ecdsa_sign_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/ecdsa_verify_boringssl.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Not;

using EcdsaSignBoringSslTestVectorTest =
    testing::TestWithParam<SignatureTestVector>;

TEST_P(EcdsaSignBoringSslTestVectorTest, CreateAndSignWithTestVectors) {
  const SignatureTestVector& param = GetParam();
  const EcdsaPrivateKey* typed_key =
      dynamic_cast<const EcdsaPrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    ASSERT_THAT(NewEcdsaSignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewEcdsaSignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewEcdsaVerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, absl::StrCat(param.message, "x")),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(EcdsaSignBoringSslTestVectorTests,
                         EcdsaSignBoringSslTestVectorTest,
                         testing::ValuesIn(CreateEcdsaTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
