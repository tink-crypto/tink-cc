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

#include "tink/signature/internal/rsa_ssa_pss_sign_boringssl.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/rsa_ssa_pss_verify_boringssl.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;

absl::StatusOr<RsaSsaPssPrivateKey> CloneKeyWithSaltLengthAndVariant(
    const RsaSsaPssPrivateKey& base_key, int salt_length_in_bytes,
    RsaSsaPssParameters::Variant variant, std::optional<int> id_requirement) {
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPssParameters parameters,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(base_key.GetParameters().GetModulusSizeInBits())
          .SetPublicExponent(base_key.GetParameters().GetPublicExponent())
          .SetSigHashType(base_key.GetParameters().GetSigHashType())
          .SetMgf1HashType(base_key.GetParameters().GetMgf1HashType())
          .SetSaltLengthInBytes(salt_length_in_bytes)
          .SetVariant(variant)
          .Build());
  ABSL_ASSIGN_OR_RETURN(
      RsaSsaPssPublicKey public_key,
      RsaSsaPssPublicKey::Create(
          parameters, base_key.GetPublicKey().GetModulus(GetPartialKeyAccess()),
          id_requirement, GetPartialKeyAccess()));
  return RsaSsaPssPrivateKey::Builder()
      .SetPublicKey(public_key)
      .SetPrimeP(base_key.GetPrimePData(GetPartialKeyAccess()))
      .SetPrimeQ(base_key.GetPrimeQData(GetPartialKeyAccess()))
      .SetPrimeExponentP(base_key.GetPrimeExponentPData())
      .SetPrimeExponentQ(base_key.GetPrimeExponentQData())
      .SetPrivateExponent(base_key.GetPrivateExponentData())
      .SetCrtCoefficient(base_key.GetCrtCoefficientData())
      .Build(GetPartialKeyAccess());
}

TEST(RsaSsaPssSignBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!IsFipsModeEnabled() || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const SignatureTestVector& test_vector = Create2048BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  EXPECT_THAT(NewRsaSsaPssSignBoringSsl(*typed_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(RsaSsaPssSignBoringSslTest, SignEmptyAndNullStringView) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes BoringCrypto when FIPS is enabled.";
  }

  const SignatureTestVector& test_vector = Create2048BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPssSignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> sig_empty = (*signer)->Sign("");
  ASSERT_THAT(sig_empty, IsOk());
  absl::StatusOr<std::string> sig_null =
      (*signer)->Sign(absl::string_view(nullptr, 0));
  ASSERT_THAT(sig_null, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPssVerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*sig_empty, ""), IsOk());
  EXPECT_THAT((*verifier)->Verify(*sig_null, ""), IsOk());
}

TEST(RsaSsaPssSignBoringSslTest, TestAllowedFipsModuli) {
  if (!IsFipsModeEnabled() || !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  const SignatureTestVector& test_vector = Create3072BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPssSignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(test_vector.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPssVerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, test_vector.message), IsOk());
}

TEST(RsaSsaPssSignBoringSslTest, MaxValidSaltLengthSucceeds) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes BoringCrypto when FIPS is enabled.";
  }

  // Create2048BitTestVector uses a 256-byte modulus with SHA-256 (32-byte
  // digest), so RFC 8017 Section 9.1.1 allows salt lengths up to
  // 256 - 32 - 2 = 222 bytes.
  constexpr int kMaxValidSaltLength = 256 - 32 - 2;
  const SignatureTestVector& test_vector = Create2048BitTestVector();
  const RsaSsaPssPrivateKey* base_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(base_key, NotNull());

  absl::StatusOr<RsaSsaPssPrivateKey> key = CloneKeyWithSaltLengthAndVariant(
      *base_key, kMaxValidSaltLength, RsaSsaPssParameters::Variant::kNoPrefix,
      /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPssSignBoringSsl(*key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign("testdata");
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPssVerifyBoringSsl(key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "testdata"), IsOk());
}

TEST(RsaSsaPssSignBoringSslTest, SaltLengthTooLargeFailsOnSign) {
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes BoringCrypto when FIPS is enabled.";
  }

  // For a 256-byte modulus and 32-byte SHA-256 digest, salt_length = 223
  // exceeds emLen - hLen - 2 (222) and causes RSA_padding_add_PKCS1_PSS_mgf1
  // to fail during Sign().
  constexpr int kExcessiveSaltLength = 256 - 32 - 2 + 1;
  const SignatureTestVector& test_vector = Create2048BitTestVector();
  const RsaSsaPssPrivateKey* base_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(base_key, NotNull());

  absl::StatusOr<RsaSsaPssPrivateKey> no_prefix_key =
      CloneKeyWithSaltLengthAndVariant(*base_key, kExcessiveSaltLength,
                                       RsaSsaPssParameters::Variant::kNoPrefix,
                                       /*id_requirement=*/std::nullopt);
  ASSERT_THAT(no_prefix_key, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> no_prefix_signer =
      NewRsaSsaPssSignBoringSsl(*no_prefix_key);
  ASSERT_THAT(no_prefix_signer, IsOk());
  EXPECT_THAT((*no_prefix_signer)->Sign("testdata"),
              StatusIs(absl::StatusCode::kInternal));

  absl::StatusOr<RsaSsaPssPrivateKey> tink_key =
      CloneKeyWithSaltLengthAndVariant(*base_key, kExcessiveSaltLength,
                                       RsaSsaPssParameters::Variant::kTink,
                                       /*id_requirement=*/0x12345678);
  ASSERT_THAT(tink_key, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeySign>> tink_signer =
      NewRsaSsaPssSignBoringSsl(*tink_key);
  ASSERT_THAT(tink_signer, IsOk());
  EXPECT_THAT((*tink_signer)->Sign("testdata"),
              StatusIs(absl::StatusCode::kInternal));
}

using RsaSsaPssSignBoringSSLTestVectorTest =
    testing::TestWithParam<SignatureTestVector>;

// RsaSsaPss is probabilistic, so we can only check that a new signature is
// verified by the verifier.
TEST_P(RsaSsaPssSignBoringSSLTestVectorTest, FreshSignatureInTestVector) {
  const SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(NewRsaSsaPssSignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(NewRsaSsaPssSignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPssSignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPssVerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());

  absl::StatusOr<std::string> second_signature = (*signer)->Sign(param.message);
  ASSERT_THAT(second_signature, IsOk());
  if (typed_key->GetParameters().GetSaltLengthInBytes() == 0) {
    EXPECT_THAT(*signature, Eq(param.signature));
    EXPECT_THAT(*second_signature, Eq(*signature));
  } else {
    EXPECT_THAT(*second_signature, Not(Eq(*signature)));
  }
}

TEST_P(RsaSsaPssSignBoringSSLTestVectorTest,
       FreshSignatureDoesNotVerifyWithDifferentMessage) {
  const SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(NewRsaSsaPssSignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    ASSERT_THAT(NewRsaSsaPssSignBoringSsl(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewRsaSsaPssSignBoringSsl(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPssVerifyBoringSsl(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, absl::StrCat(param.message, "x")),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(RsaSsaPssSignBoringSSLTestVectorTest,
                         RsaSsaPssSignBoringSSLTestVectorTest,
                         testing::ValuesIn(CreateRsaSsaPssTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
