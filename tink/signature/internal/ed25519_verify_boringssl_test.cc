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

#include "tink/signature/internal/ed25519_verify_boringssl.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Not;

using Ed25519VerifyBoringSslTestVectorTest =
    testing::TestWithParam<SignatureTestVector>;

TEST_P(Ed25519VerifyBoringSslTestVectorTest, VerifyTestVectors) {
  const SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());
  if (IsFipsModeEnabled()) {
    EXPECT_THAT(NewEd25519VerifyBoringSsl(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewEd25519VerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(Ed25519VerifyBoringSslTestVectorTest, VerifyFailsWithModifiedSignature) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewEd25519VerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string modified_signature = param.signature;
  for (size_t i = 0; i < modified_signature.size(); ++i) {
    modified_signature[i] ^= 0x01;
    EXPECT_THAT((*verifier)->Verify(modified_signature, param.message),
                Not(IsOk()));
    modified_signature[i] ^= 0x01;
  }
}

TEST_P(Ed25519VerifyBoringSslTestVectorTest, VerifyFailsWithModifiedMessage) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewEd25519VerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(param.signature,
                                  absl::StrCat(param.message, "modified")),
              Not(IsOk()));
}

TEST_P(Ed25519VerifyBoringSslTestVectorTest,
       VerifyFailsWithTruncatedSignature) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewEd25519VerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  for (size_t len = 0; len < param.signature.size(); ++len) {
    EXPECT_THAT(
        (*verifier)->Verify(absl::string_view(param.signature).substr(0, len),
                            param.message),
        Not(IsOk()));
  }
}

INSTANTIATE_TEST_SUITE_P(Ed25519VerifyBoringSslTestVectorTests,
                         Ed25519VerifyBoringSslTestVectorTest,
                         testing::ValuesIn(CreateEd25519TestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
