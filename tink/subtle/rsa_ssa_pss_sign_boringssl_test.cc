// Copyright 2018 Google LLC
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

#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"

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
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::NotNull;

TEST(RsaPssSignBoringsslTest, EncodesPss) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const internal::SignatureTestVector& test_vector =
      internal::Create2048BitTestVector();
  const auto* private_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPssSignBoringSsl::New(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("testdata");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Not(IsEmpty()));

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "testdata"), IsOk());
}

TEST(RsaPssSignBoringsslTest, EncodesPssWithSha384) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const auto* sha384_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      internal::GetRsaSsaPssTestVector(2048,
                                       RsaSsaPssParameters::HashType::kSha384,
                                       RsaSsaPssParameters::Variant::kNoPrefix)
          .signature_private_key.get());
  ASSERT_THAT(sha384_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPssSignBoringSsl::New(*sha384_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("testdata");
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(sha384_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "testdata"), IsOk());

  const auto* sha256_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      internal::GetRsaSsaPssTestVector(2048,
                                       RsaSsaPssParameters::HashType::kSha256,
                                       RsaSsaPssParameters::Variant::kNoPrefix)
          .signature_private_key.get());
  ASSERT_THAT(sha256_key, NotNull());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> sha256_verifier =
      RsaSsaPssVerifyBoringSsl::New(sha256_key->GetPublicKey());
  ASSERT_THAT(sha256_verifier, IsOk());
  EXPECT_THAT((*sha256_verifier)->Verify(*signature, "testdata"), Not(IsOk()));
}

TEST(RsaPssSignBoringsslTest, EncodesPssWithSha512) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const auto* sha512_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      internal::GetRsaSsaPssTestVector(2048,
                                       RsaSsaPssParameters::HashType::kSha512,
                                       RsaSsaPssParameters::Variant::kNoPrefix)
          .signature_private_key.get());
  ASSERT_THAT(sha512_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPssSignBoringSsl::New(*sha512_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("testdata");
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(sha512_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "testdata"), IsOk());

  const auto* sha384_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      internal::GetRsaSsaPssTestVector(2048,
                                       RsaSsaPssParameters::HashType::kSha384,
                                       RsaSsaPssParameters::Variant::kNoPrefix)
          .signature_private_key.get());
  ASSERT_THAT(sha384_key, NotNull());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> sha384_verifier =
      RsaSsaPssVerifyBoringSsl::New(sha384_key->GetPublicKey());
  ASSERT_THAT(sha384_verifier, IsOk());
  EXPECT_THAT((*sha384_verifier)->Verify(*signature, "testdata"), Not(IsOk()));
}

// FIPS-only mode test
TEST(RsaPssSignBoringsslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const internal::SignatureTestVector& test_vector =
      internal::Create2048BitTestVector();
  const auto* private_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(private_key, NotNull());
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(*private_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(RsaPssSignBoringsslTest, TestAllowedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }
  const internal::SignatureTestVector& test_vector =
      internal::Create3072BitTestVector();
  const auto* typed_key = dynamic_cast<const RsaSsaPssPrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(*typed_key).status(), IsOk());
}

using RsaSsaPssSignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// RsaSsaPss is probabilistic, so we can only check that a new signature is
// verified by the verifier.
TEST_P(RsaSsaPssSignBoringSSLTestVectorTest, FreshSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPssSignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPssSignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPssSignBoringSsl::New(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());

  // Also check that the verifier doesn't simply verify everything: we change
  // the message.
  EXPECT_THAT((*verifier)->Verify(*signature, absl::StrCat(param.message, "x")),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssSignBoringSSLTestVectorTest,
    RsaSsaPssSignBoringSSLTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPssTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
