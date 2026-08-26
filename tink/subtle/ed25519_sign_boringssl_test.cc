// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/secret_data.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/ed25519_verify_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;

constexpr int kEd25519SignatureLenInBytes = 64;

class Ed25519SignBoringSslTest : public ::testing::Test {
 protected:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
    }
  }

  Ed25519SignBoringSslTest() {
    const internal::SignatureTestVector& test_vector =
        internal::GetEd25519TestVector(Ed25519Parameters::Variant::kNoPrefix);
    const Ed25519PrivateKey* typed_key = dynamic_cast<const Ed25519PrivateKey*>(
        test_vector.signature_private_key.get());
    ABSL_CHECK(typed_key != nullptr);
    public_key_ = std::string(
        typed_key->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
    absl::string_view priv_bytes =
        typed_key->GetPrivateKeyBytes(GetPartialKeyAccess())
            .GetSecret(InsecureSecretKeyAccess::Get());
    private_key_ =
        util::SecretDataFromStringView(absl::StrCat(priv_bytes, public_key_));
  }

  std::string public_key_;
  SecretData private_key_;
};

TEST_F(Ed25519SignBoringSslTest, testBasicSign) {
  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(private_key_);
  ASSERT_THAT(signer_result, IsOk());
  auto signer = std::move(signer_result.value());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(public_key_);
  ASSERT_THAT(verifier_result, IsOk());
  auto verifier = std::move(verifier_result.value());

  // Sign a message.
  std::string message = "some data to be signed";
  std::string signature = signer->Sign(message).value();
  EXPECT_NE(signature, message);
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  auto status = verifier->Verify(signature, message);
  EXPECT_THAT(status, IsOk());

  status = verifier->Verify("some bad signature", message);
  EXPECT_THAT(status, Not(IsOk()));

  status = verifier->Verify(signature, "some bad message");
  EXPECT_THAT(status, Not(IsOk()));

  // Loop 100 times, sign a random message twice using the signer and verify
  // that the signatures are the same.
  for (size_t i = 0; i < 100; i++) {
    message = subtle::Random::GetRandomBytes(i);
    std::string signature1 = signer->Sign(message).value();
    std::string signature2 = signer->Sign(message).value();
    EXPECT_EQ(signature1, signature2);
    // Verify that the signatures are valid.
    status = verifier->Verify(signature1, message);
    EXPECT_THAT(status, IsOk());
  }
}

TEST_F(Ed25519SignBoringSslTest, testInvalidPrivateKeys) {
  for (int keysize = 0; keysize < 128; keysize++) {
    // Ed25519SignBoringSsl::New expects a private key: private part || public
    // part.
    if (keysize ==
        internal::Ed25519KeyPrivKeySize() + internal::Ed25519KeyPubKeySize()) {
      // Valid key size.
      continue;
    }
    SecretData key(keysize, 'x');
    EXPECT_THAT(Ed25519SignBoringSsl::New(key), Not(IsOk()));
  }
}

TEST_F(Ed25519SignBoringSslTest, testMessageEmptyVersusNullStringView) {
  // Create a new signer.
  auto signer_result = Ed25519SignBoringSsl::New(private_key_);
  ASSERT_THAT(signer_result, IsOk());
  auto signer = std::move(signer_result.value());

  // Create a new verifier.
  auto verifier_result = Ed25519VerifyBoringSsl::New(public_key_);
  ASSERT_THAT(verifier_result, IsOk());
  auto verifier = std::move(verifier_result.value());

  // Message is a null string_view.
  const absl::string_view empty_message;
  auto signature = signer->Sign(empty_message).value();
  EXPECT_NE(signature, empty_message);
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  auto status = verifier->Verify(signature, empty_message);
  EXPECT_THAT(status, IsOk());

  // Message is an empty string.
  const std::string message = "";
  signature = signer->Sign(message).value();
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  EXPECT_NE(signature, message);
  status = verifier->Verify(signature, message);
  EXPECT_THAT(status, IsOk());

  // Message is a default constructed string_view.
  signature = signer->Sign(absl::string_view()).value();
  EXPECT_EQ(signature.size(), kEd25519SignatureLenInBytes);
  status = verifier->Verify(signature, absl::string_view());
  EXPECT_THAT(status, IsOk());
}

TEST(Ed25519SignBoringSslFipsTest, testFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  SecretData dummy_key(64, 'x');
  EXPECT_THAT(Ed25519SignBoringSsl::New(dummy_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

using Ed25519SignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// Ed25519 is deterministic, so we can compute the signature.
TEST_P(Ed25519SignBoringSSLTestVectorTest, ComputeSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled()) {
    // Users wants FIPS but Ed25519 is not FIPS
    ASSERT_THAT(Ed25519SignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      Ed25519SignBoringSsl::New(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

INSTANTIATE_TEST_SUITE_P(
    Ed25519SignBoringSSLTestVectorTest,
    Ed25519SignBoringSSLTestVectorTest,
    testing::ValuesIn(internal::CreateEd25519TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
