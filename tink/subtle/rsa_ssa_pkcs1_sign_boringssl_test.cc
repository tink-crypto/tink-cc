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

#include "tink/subtle/rsa_ssa_pkcs1_sign_boringssl.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/rsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::NotNull;

class RsaPkcs1SignBoringsslTest : public ::testing::Test {
 public:
  RsaPkcs1SignBoringsslTest() : rsa_f4_(BN_new()) {
    EXPECT_TRUE(BN_set_word(rsa_f4_.get(), RSA_F4));
    EXPECT_THAT(
        internal::NewRsaKeyPair(/*modulus_size_in_bits=*/2048, rsa_f4_.get(),
                                &private_key_, &public_key_),
        IsOk());
  }

 protected:
  internal::SslUniquePtr<BIGNUM> rsa_f4_;
  internal::RsaPrivateKey private_key_;
  internal::RsaPublicKey public_key_;
};

TEST_F(RsaPkcs1SignBoringsslTest, EncodesPkcs1) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};

  auto signer_or = RsaSsaPkcs1SignBoringSsl::New(private_key_, params);
  ASSERT_THAT(signer_or, IsOk());

  auto signature_or = signer_or.value()->Sign("testdata");
  ASSERT_THAT(signature_or, IsOk());
  EXPECT_THAT(signature_or.value(), Not(IsEmpty()));

  auto verifier_or = RsaSsaPkcs1VerifyBoringSsl::New(public_key_, params);
  ASSERT_THAT(verifier_or, IsOk());
  EXPECT_THAT(verifier_or.value()->Verify(signature_or.value(), "testdata"),
              IsOk());
}

TEST_F(RsaPkcs1SignBoringsslTest, EncodesPkcs1WithSeparateHashes) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};

  auto signer_or = RsaSsaPkcs1SignBoringSsl::New(private_key_, params);
  ASSERT_THAT(signer_or, IsOk());

  auto signature_or = signer_or.value()->Sign("testdata");
  ASSERT_THAT(signature_or, IsOk());
  EXPECT_THAT(signature_or.value(), Not(IsEmpty()));

  auto verifier_or = RsaSsaPkcs1VerifyBoringSsl::New(public_key_, params);
  ASSERT_THAT(verifier_or, IsOk());
  EXPECT_THAT(verifier_or.value()->Verify(signature_or.value(), "testdata"),
              IsOk());
}

TEST_F(RsaPkcs1SignBoringsslTest, RejectsUnsafeHash) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA1};
  ASSERT_THAT(RsaSsaPkcs1SignBoringSsl::New(private_key_, params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaPkcs1SignBoringsslTest, RejectsInvalidCrtParams) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  ASSERT_THAT(private_key_.crt, Not(IsEmpty()));
  ASSERT_THAT(private_key_.dq, Not(IsEmpty()));
  ASSERT_THAT(private_key_.dp, Not(IsEmpty()));

  // Flip a few bits in the CRT parameters; check that creation fails.
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer crt_buffer = util::internal::AsSecretBuffer(key.crt);
    crt_buffer[0] ^= 0x80;
    key.crt = util::internal::AsSecretData(crt_buffer);
    auto signer_or = RsaSsaPkcs1SignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer dq_buffer = util::internal::AsSecretBuffer(key.dq);
    dq_buffer[0] ^= 0x08;
    key.dq = util::internal::AsSecretData(dq_buffer);
    auto signer_or = RsaSsaPkcs1SignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    internal::RsaPrivateKey key = private_key_;
    internal::SecretBuffer dp_buffer = util::internal::AsSecretBuffer(key.dp);
    dp_buffer[0] ^= 0x04;
    key.dp = util::internal::AsSecretData(dp_buffer);
    auto signer_or = RsaSsaPkcs1SignBoringSsl::New(key, params);
    EXPECT_THAT(signer_or.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

// FIPS-only mode test
TEST_F(RsaPkcs1SignBoringsslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1SignBoringSsl::New(private_key_, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaPkcs1SignBoringsslTest, TestRestrictedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;

  EXPECT_THAT(internal::NewRsaKeyPair(/*modulus_size_in_bits=*/4096,
                                      rsa_f4_.get(), &private_key, &public_key),
              IsOk());

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1SignBoringSsl::New(private_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaPkcs1SignBoringsslTest, TestAllowedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;

  EXPECT_THAT(internal::NewRsaKeyPair(/*modulus_size_in_bits=*/3072,
                                      rsa_f4_.get(), &private_key, &public_key),
              IsOk());

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1SignBoringSsl::New(private_key, params).status(),
              IsOk());
}

using RsaSsaPkcs1SignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// RsaSsaPkcs1 is deterministic, so we can compute the signature.
TEST_P(RsaSsaPkcs1SignBoringSSLTestVectorTest, ComputeSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPkcs1SignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPkcs1SignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  util::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      RsaSsaPkcs1SignBoringSsl::New(*typed_key);
  ASSERT_THAT(signer, IsOk());
  util::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1SignBoringSSLTestVectorTest,
    RsaSsaPkcs1SignBoringSSLTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPkcs1TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
