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
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Not;

class EcdsaSignBoringSslTest : public ::testing::Test {};

TEST_F(EcdsaSignBoringSslTest, testBasicSigning) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key =
        SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    std::string signature = signer->Sign(message).value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_TRUE(status.ok()) << status;

    status = verifier->Verify("some bad signature", message);
    EXPECT_FALSE(status.ok());

    status = verifier->Verify(signature, "some bad message");
    EXPECT_FALSE(status.ok());

    // Message is a null string_view.
    const absl::string_view empty_message;
    signature = signer->Sign(empty_message).value();
    EXPECT_NE(signature, empty_message);
    status = verifier->Verify(signature, empty_message);
    EXPECT_TRUE(status.ok()) << status;
  }
}

TEST_F(EcdsaSignBoringSslTest, testEncodingsMismatch) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    auto ec_key =
        SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                  encoding == EcdsaSignatureEncoding::DER
                                      ? EcdsaSignatureEncoding::IEEE_P1363
                                      : EcdsaSignatureEncoding::DER);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    std::string signature = signer->Sign(message).value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_FALSE(status.ok()) << status;
  }
}

TEST_F(EcdsaSignBoringSslTest, testSignatureSizesWithIEEE_P1364Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EllipticCurveType curves[3] = {EllipticCurveType::NIST_P256,
                                 EllipticCurveType::NIST_P384,
                                 EllipticCurveType::NIST_P521};
  for (EllipticCurveType curve : curves) {
    auto ec_key = SubtleUtilBoringSSL::GetNewEcKey(curve).value();
    auto signer_result = EcdsaSignBoringSsl::New(
        ec_key, HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_TRUE(signer_result.ok()) << signer_result.status();
    auto signer = std::move(signer_result.value());

    auto verifier_result = EcdsaVerifyBoringSsl::New(
        ec_key, HashType::SHA256, EcdsaSignatureEncoding::IEEE_P1363);
    ASSERT_TRUE(verifier_result.ok()) << verifier_result.status();
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    std::string signature = signer->Sign(message).value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_TRUE(status.ok()) << status;

    // Check signature size.
    absl::StatusOr<int32_t> field_size_in_bytes =
        internal::EcFieldSizeInBytes(curve);
    ASSERT_THAT(field_size_in_bytes, IsOk());
    EXPECT_EQ(signature.size(), 2 * (*field_size_in_bytes));
  }
}

TEST_F(EcdsaSignBoringSslTest, testNewErrors) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  auto ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
  auto signer_result = EcdsaSignBoringSsl::New(ec_key, HashType::SHA1,
                                               EcdsaSignatureEncoding::DER);
  EXPECT_FALSE(signer_result.ok()) << signer_result.status();
}

// TODO(bleichen): add Wycheproof tests.

// FIPS-only mode test
TEST_F(EcdsaSignBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  auto ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256).value();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P384).value();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P521).value();
  EXPECT_THAT(EcdsaSignBoringSsl::New(ec_key, HashType::SHA256,
                                      EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

using EcdsaSignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

// ECDSA is probabilistic, so we can only check that a new signature is
// verified by the verifier.
TEST_P(EcdsaSignBoringSSLTestVectorTest, FreshSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const EcdsaPrivateKey* typed_key =
      dynamic_cast<const EcdsaPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, testing::NotNull());
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

INSTANTIATE_TEST_SUITE_P(
    EcdsaSignBoringSSLTestVectorTest,
    EcdsaSignBoringSSLTestVectorTest,
    testing::ValuesIn(internal::CreateEcdsaTestVectors()));



}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
