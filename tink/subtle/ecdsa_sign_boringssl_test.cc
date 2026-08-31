// Copyright 2017 Google LLC
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

#include "tink/subtle/ecdsa_sign_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Values;
using ::testing::ValuesIn;

using EcdsaSignBasicTest =
    testing::TestWithParam<subtle::EcdsaSignatureEncoding>;
using EcdsaSignSignatureSizeTest = testing::TestWithParam<EllipticCurveType>;
using EcdsaSignFipsFailTest = testing::TestWithParam<EllipticCurveType>;
using EcdsaSignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

INSTANTIATE_TEST_SUITE_P(EcdsaSignBasicTests, EcdsaSignBasicTest,
                         Values(EcdsaSignatureEncoding::DER,
                                EcdsaSignatureEncoding::IEEE_P1363));

TEST_P(EcdsaSignBasicTest, BasicSigning) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encoding = GetParam();
  const internal::EcKey& ec_key =
      internal::GetEcKey(EllipticCurveType::NIST_P256);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, encoding);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "some data to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_NE(*signature, message);
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());

  EXPECT_THAT((*verifier)->Verify("some bad signature", message), Not(IsOk()));
  EXPECT_THAT((*verifier)->Verify(*signature, "some bad message"), Not(IsOk()));

  // Message is a null string_view.
  const absl::string_view empty_message;
  absl::StatusOr<std::string> empty_sig = (*signer)->Sign(empty_message);
  ASSERT_THAT(empty_sig, IsOk());
  EXPECT_NE(*empty_sig, empty_message);
  EXPECT_THAT((*verifier)->Verify(*empty_sig, empty_message), IsOk());
}

TEST_P(EcdsaSignBasicTest, EncodingsMismatch) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encoding = GetParam();
  const internal::EcKey& ec_key =
      internal::GetEcKey(EllipticCurveType::NIST_P256);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
  ASSERT_THAT(signer, IsOk());

  subtle::EcdsaSignatureEncoding mismatched_encoding =
      encoding == EcdsaSignatureEncoding::DER
          ? EcdsaSignatureEncoding::IEEE_P1363
          : EcdsaSignatureEncoding::DER;
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, mismatched_encoding);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "some data to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_NE(*signature, message);
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(EcdsaSignSignatureSizeTests,
                         EcdsaSignSignatureSizeTest,
                         Values(EllipticCurveType::NIST_P256,
                                EllipticCurveType::NIST_P384,
                                EllipticCurveType::NIST_P521));

TEST_P(EcdsaSignSignatureSizeTest, SignatureSizesWithIeeeP1363Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EllipticCurveType curve = GetParam();
  const internal::EcKey& ec_key = internal::GetEcKey(curve);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                              EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                EcdsaSignatureEncoding::IEEE_P1363);
  ASSERT_THAT(verifier, IsOk());

  std::string message = "some data to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_NE(*signature, message);
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());

  // Check signature size.
  absl::StatusOr<int32_t> field_size_in_bytes =
      internal::EcFieldSizeInBytes(curve);
  ASSERT_THAT(field_size_in_bytes, IsOk());
  EXPECT_EQ(signature->size(), 2 * (*field_size_in_bytes));
}

TEST(EcdsaSignBoringSslTest, NewErrors) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  const internal::EcKey& ec_key =
      internal::GetEcKey(EllipticCurveType::NIST_P256);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(ec_key, HashType::SHA1,
                              EcdsaSignatureEncoding::DER);
  EXPECT_THAT(signer, Not(IsOk()));
}

// FIPS-only mode test
INSTANTIATE_TEST_SUITE_P(EcdsaSignFipsFailTests, EcdsaSignFipsFailTest,
                         Values(EllipticCurveType::NIST_P256,
                                EllipticCurveType::NIST_P384,
                                EllipticCurveType::NIST_P521));

TEST_P(EcdsaSignFipsFailTest, FipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  EllipticCurveType curve = GetParam();
  const internal::EcKey& ec_key = internal::GetEcKey(curve);
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

INSTANTIATE_TEST_SUITE_P(EcdsaSignBoringSSLTestVectorTest,
                         EcdsaSignBoringSSLTestVectorTest,
                         ValuesIn(internal::CreateEcdsaTestVectors()));

// ECDSA is probabilistic, so we can only check that a new signature is
// verified by the verifier.
TEST_P(EcdsaSignBoringSSLTestVectorTest, FreshSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const EcdsaPrivateKey* typed_key =
      dynamic_cast<const EcdsaPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(EcdsaSignBoringSsl::New(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());

  // Also check that the verifier doesn't simply verify everything: we change
  // the message.
  EXPECT_THAT((*verifier)->Verify(*signature, absl::StrCat(param.message, "x")),
              Not(IsOk()));
}



}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
