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

#include "tink/signature/subtle/create_ed25519_verifier.h"

#include <cstddef>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
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
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::internal::CreateEd25519TestVectors;
using ::crypto::tink::internal::SignatureTestVector;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

class CreateEd25519PublicKeyVerifyTestVectorTest
    : public TestWithParam<SignatureTestVector> {};

TEST_P(CreateEd25519PublicKeyVerifyTestVectorTest, VerifyTestVectors) {
  const SignatureTestVector& test_vector = GetParam();
  const Ed25519PrivateKey& private_key = dynamic_cast<const Ed25519PrivateKey&>(
      *test_vector.signature_private_key);
  if (internal::IsFipsModeEnabled()) {
    EXPECT_THAT(CreateEd25519PublicKeyVerify(private_key.GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEd25519PublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature, test_vector.message),
              IsOk());
}

TEST_P(CreateEd25519PublicKeyVerifyTestVectorTest,
       VerifyFailsWithModifiedSignature) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Ed25519 is not supported in FIPS mode.";
  }
  const SignatureTestVector& test_vector = GetParam();
  const Ed25519PrivateKey& private_key = dynamic_cast<const Ed25519PrivateKey&>(
      *test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEd25519PublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  for (size_t i = 0; i < test_vector.signature.size(); ++i) {
    SCOPED_TRACE(absl::StrCat("i=", i));
    std::string modified_signature = test_vector.signature;
    modified_signature[i] ^= 0x01;
    EXPECT_THAT((*verifier)->Verify(modified_signature, test_vector.message),
                Not(IsOk()));
  }
}

TEST_P(CreateEd25519PublicKeyVerifyTestVectorTest,
       VerifyFailsWithModifiedMessage) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Ed25519 is not supported in FIPS mode.";
  }
  const SignatureTestVector& test_vector = GetParam();
  const Ed25519PrivateKey& private_key = dynamic_cast<const Ed25519PrivateKey&>(
      *test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEd25519PublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(test_vector.signature,
                                  absl::StrCat(test_vector.message, "a")),
              Not(IsOk()));
}

TEST_P(CreateEd25519PublicKeyVerifyTestVectorTest,
       VerifyFailsWithTruncatedOrExtendedSignature) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Ed25519 is not supported in FIPS mode.";
  }
  const SignatureTestVector& test_vector = GetParam();
  const Ed25519PrivateKey& private_key = dynamic_cast<const Ed25519PrivateKey&>(
      *test_vector.signature_private_key);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateEd25519PublicKeyVerify(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  for (size_t len = 0; len < test_vector.signature.size(); ++len) {
    SCOPED_TRACE(absl::StrCat("len=", len));
    EXPECT_THAT((*verifier)->Verify(
                    absl::string_view(test_vector.signature).substr(0, len),
                    test_vector.message),
                Not(IsOk()));
  }
  EXPECT_THAT((*verifier)->Verify(absl::StrCat(test_vector.signature, "a"),
                                  test_vector.message),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(CreateEd25519PublicKeyVerifyTestVectorTests,
                         CreateEd25519PublicKeyVerifyTestVectorTest,
                         ValuesIn(CreateEd25519TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
