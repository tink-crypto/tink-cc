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

#include "tink/signature/internal/rsa_ssa_pkcs1_sign_boringssl.h"

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
#include "tink/public_key_verify.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;

TEST(RsaSsaPkcs1SignBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector = Create2048BitsTestVector();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  EXPECT_THAT(NewRsaSsaPkcs1SignBoringSsl(*typed_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(RsaSsaPkcs1SignBoringSslTest, SignEmptyAndNullStringView) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes BoringCrypto when FIPS is enabled.";
  }

  const SignatureTestVector& test_vector = Create2048BitsTestVector();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPkcs1SignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> sig_empty = (*signer)->Sign("");
  ASSERT_THAT(sig_empty, IsOk());
  EXPECT_THAT((*signer)->Sign(absl::string_view(nullptr, 0)),
              IsOkAndHolds(Eq(*sig_empty)));

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPkcs1VerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*sig_empty, ""), IsOk());
}

using RsaSsaPkcs1SignBoringSSLTestVectorTest =
    testing::TestWithParam<SignatureTestVector>;

// RsaSsaPkcs1 is deterministic, so we can compute the signature.
TEST_P(RsaSsaPkcs1SignBoringSSLTestVectorTest, ComputeSignatureInTestVector) {
  const SignatureTestVector& param = GetParam();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(NewRsaSsaPkcs1SignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(NewRsaSsaPkcs1SignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPkcs1SignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

INSTANTIATE_TEST_SUITE_P(RsaSsaPkcs1SignBoringSSLTestVectorTest,
                         RsaSsaPkcs1SignBoringSSLTestVectorTest,
                         testing::ValuesIn(CreateRsaSsaPkcs1TestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
