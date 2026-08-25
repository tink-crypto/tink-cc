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
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::NotNull;

internal::RsaPrivateKey ToRsaPrivateKey(const RsaSsaPssPrivateKey& key) {
  internal::RsaPrivateKey private_key;
  private_key.n = std::string(
      key.GetPublicKey().GetModulus(GetPartialKeyAccess()).GetValue());
  private_key.e = std::string(
      key.GetPublicKey().GetParameters().GetPublicExponent().GetValue());
  private_key.d =
      key.GetPrivateExponentData().Get(InsecureSecretKeyAccess::Get());
  private_key.p = key.GetPrimePData().Get(InsecureSecretKeyAccess::Get());
  private_key.q = key.GetPrimeQData().Get(InsecureSecretKeyAccess::Get());
  private_key.dp =
      key.GetPrimeExponentPData().Get(InsecureSecretKeyAccess::Get());
  private_key.dq =
      key.GetPrimeExponentQData().Get(InsecureSecretKeyAccess::Get());
  private_key.crt =
      key.GetCrtCoefficientData().Get(InsecureSecretKeyAccess::Get());
  return private_key;
}

internal::RsaPublicKey ToRsaPublicKey(const RsaSsaPssPublicKey& key) {
  internal::RsaPublicKey public_key;
  public_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key.e =
      std::string(key.GetParameters().GetPublicExponent().GetValue());
  return public_key;
}

class RsaPssSignBoringsslTest : public ::testing::Test {
 public:
  RsaPssSignBoringsslTest() {
    const internal::SignatureTestVector& test_vector =
        internal::Create2048BitTestVector();
    const RsaSsaPssPrivateKey* typed_key =
        dynamic_cast<const RsaSsaPssPrivateKey*>(
            test_vector.signature_private_key.get());
    ABSL_CHECK(typed_key != nullptr);
    private_key_ = ToRsaPrivateKey(*typed_key);
    public_key_ = ToRsaPublicKey(typed_key->GetPublicKey());
  }

 protected:
  internal::RsaPrivateKey private_key_;
  internal::RsaPublicKey public_key_;
};

TEST_F(RsaPssSignBoringsslTest, EncodesPss) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/32};

  auto signer_or = RsaSsaPssSignBoringSsl::New(private_key_, params);
  ASSERT_THAT(signer_or, IsOk());

  auto signature_or = signer_or.value()->Sign("testdata");
  ASSERT_THAT(signature_or, IsOk());
  EXPECT_THAT(signature_or.value(), Not(IsEmpty()));

  auto verifier_or = RsaSsaPssVerifyBoringSsl::New(public_key_, params);
  ASSERT_THAT(verifier_or, IsOk());
  EXPECT_THAT(verifier_or.value()->Verify(signature_or.value(), "testdata"),
              IsOk());
}

TEST_F(RsaPssSignBoringsslTest, EncodesPssWithSeparateHashes) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA1,
                                   /*salt_length=*/32};

  auto signer_or = RsaSsaPssSignBoringSsl::New(private_key_, params);
  ASSERT_THAT(signer_or, IsOk());

  auto signature_or = signer_or.value()->Sign("testdata");
  ASSERT_THAT(signature_or, IsOk());
  EXPECT_THAT(signature_or.value(), Not(IsEmpty()));

  auto verifier_or = RsaSsaPssVerifyBoringSsl::New(public_key_, params);
  ASSERT_THAT(verifier_or, IsOk());
  EXPECT_THAT(verifier_or.value()->Verify(signature_or.value(), "testdata"),
              IsOk());
}

TEST_F(RsaPssSignBoringsslTest, NegativeSaltLengthFails) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/-1};
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(private_key_, params),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("Salt length is negative")));
}

TEST_F(RsaPssSignBoringsslTest, RejectsInvalidPaddingHash) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::UNKNOWN_HASH,
                                   /*salt_length=*/0};
  ASSERT_THAT(RsaSsaPssSignBoringSsl::New(private_key_, params).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST_F(RsaPssSignBoringsslTest, RejectsUnsafePaddingHash) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA1,
                                   /*mgf1_hash=*/HashType::SHA1,
                                   /*salt_length=*/0};
  ASSERT_THAT(RsaSsaPssSignBoringSsl::New(private_key_, params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaPssSignBoringsslTest, RejectsInvalidCrtParams) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/32};
  ASSERT_THAT(private_key_.crt, Not(IsEmpty()));
  ASSERT_THAT(private_key_.dq, Not(IsEmpty()));
  ASSERT_THAT(private_key_.dp, Not(IsEmpty()));

  // Flip a few bits in the CRT parameters; check that creation fails.
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer crt_buffer = util::internal::AsSecretBuffer(key.crt);
    crt_buffer[0] ^= 0x80;
    key.crt = util::internal::AsSecretData(crt_buffer);
    auto signer_or = RsaSsaPssSignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer dq_buffer = util::internal::AsSecretBuffer(key.dq);
    dq_buffer[0] ^= 0x08;
    key.dq = util::internal::AsSecretData(dq_buffer);
    auto signer_or = RsaSsaPssSignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer dp_buffer = util::internal::AsSecretBuffer(key.dp);
    dp_buffer[0] ^= 0x04;
    key.dp = util::internal::AsSecretData(dp_buffer);
    auto signer_or = RsaSsaPssSignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

// FIPS-only mode test
TEST_F(RsaPssSignBoringsslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/32};
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(private_key_, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaPssSignBoringsslTest, TestRestrictedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  // Create a random 4096-bit modulus and 65537 public exponent.
  internal::RsaPrivateKey private_key;
  private_key.n = std::string(512, '\x80');
  private_key.e = "\x01\x00\x01";

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/32};
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(private_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaPssSignBoringsslTest, TestAllowedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }
  const internal::SignatureTestVector& test_vector =
      internal::Create3072BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  internal::RsaPrivateKey private_key = ToRsaPrivateKey(*typed_key);

  internal::RsaSsaPssParams params{/*sig_hash=*/HashType::SHA256,
                                   /*mgf1_hash=*/HashType::SHA256,
                                   /*salt_length=*/32};
  EXPECT_THAT(RsaSsaPssSignBoringSsl::New(private_key, params).status(),
              IsOk());
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
      typed_key->GetParameters().GetModulusSizeInBits() != 3072) {
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
