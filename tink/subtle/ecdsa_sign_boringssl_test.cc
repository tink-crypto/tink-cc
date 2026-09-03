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

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
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
    testing::TestWithParam<EcdsaParameters::SignatureEncoding>;
using EcdsaSignSignatureSizeTest =
    testing::TestWithParam<EcdsaParameters::CurveType>;
using EcdsaSignFipsFailTest =
    testing::TestWithParam<EcdsaParameters::CurveType>;
using EcdsaSignBoringSSLTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

int EcFieldSizeInBytes(EcdsaParameters::CurveType curve) {
  switch (curve) {
    case EcdsaParameters::CurveType::kNistP256:
      return 32;
    case EcdsaParameters::CurveType::kNistP384:
      return 48;
    case EcdsaParameters::CurveType::kNistP521:
      return 66;
    default:
      ABSL_CHECK(false) << "Unsupported curve: " << static_cast<int>(curve);
  }
}

const EcdsaPrivateKey& GetPrivateKey(
    EcdsaParameters::CurveType curve,
    EcdsaParameters::SignatureEncoding encoding =
        EcdsaParameters::SignatureEncoding::kIeeeP1363) {
  EcdsaParameters::HashType hash_type;
  switch (curve) {
    case EcdsaParameters::CurveType::kNistP256:
      hash_type = EcdsaParameters::HashType::kSha256;
      break;
    case EcdsaParameters::CurveType::kNistP384:
      hash_type = EcdsaParameters::HashType::kSha384;
      break;
    case EcdsaParameters::CurveType::kNistP521:
      hash_type = EcdsaParameters::HashType::kSha512;
      break;
    default:
      ABSL_CHECK(false) << "Unsupported curve: " << static_cast<int>(curve);
  }
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(curve, hash_type, encoding,
                                   EcdsaParameters::Variant::kNoPrefix);
  return *dynamic_cast<const EcdsaPrivateKey*>(
      test_vector.signature_private_key.get());
}

INSTANTIATE_TEST_SUITE_P(
    EcdsaSignBasicTests, EcdsaSignBasicTest,
    Values(EcdsaParameters::SignatureEncoding::kDer,
           EcdsaParameters::SignatureEncoding::kIeeeP1363));

TEST_P(EcdsaSignBasicTest, BasicSigning) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EcdsaParameters::SignatureEncoding encoding = GetParam();
  const EcdsaPrivateKey& private_key =
      GetPrivateKey(EcdsaParameters::CurveType::kNistP256, encoding);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(private_key.GetPublicKey());
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
  EcdsaParameters::SignatureEncoding encoding = GetParam();
  const EcdsaPrivateKey& private_key =
      GetPrivateKey(EcdsaParameters::CurveType::kNistP256, encoding);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(private_key);
  ASSERT_THAT(signer, IsOk());

  EcdsaParameters::SignatureEncoding mismatched_encoding =
      encoding == EcdsaParameters::SignatureEncoding::kDer
          ? EcdsaParameters::SignatureEncoding::kIeeeP1363
          : EcdsaParameters::SignatureEncoding::kDer;
  const EcdsaPrivateKey& mismatched_key =
      GetPrivateKey(EcdsaParameters::CurveType::kNistP256, mismatched_encoding);
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(mismatched_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message = "some data to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_NE(*signature, message);
  EXPECT_THAT((*verifier)->Verify(*signature, message), Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(EcdsaSignSignatureSizeTests,
                         EcdsaSignSignatureSizeTest,
                         Values(EcdsaParameters::CurveType::kNistP256,
                                EcdsaParameters::CurveType::kNistP384,
                                EcdsaParameters::CurveType::kNistP521));

TEST_P(EcdsaSignSignatureSizeTest, SignatureSizesWithIeeeP1363Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  EcdsaParameters::CurveType curve = GetParam();
  const EcdsaPrivateKey& private_key =
      GetPrivateKey(curve, EcdsaParameters::SignatureEncoding::kIeeeP1363);
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      EcdsaSignBoringSsl::New(private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(private_key.GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message = "some data to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_NE(*signature, message);
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());

  // Check signature size.
  EXPECT_EQ(signature->size(), 2 * EcFieldSizeInBytes(curve));
}

// FIPS-only mode test
INSTANTIATE_TEST_SUITE_P(EcdsaSignFipsFailTests, EcdsaSignFipsFailTest,
                         Values(EcdsaParameters::CurveType::kNistP256,
                                EcdsaParameters::CurveType::kNistP384,
                                EcdsaParameters::CurveType::kNistP521));

TEST_P(EcdsaSignFipsFailTest, FipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  EcdsaParameters::CurveType curve = GetParam();
  const EcdsaPrivateKey& key =
      GetPrivateKey(curve, EcdsaParameters::SignatureEncoding::kIeeeP1363);
  EXPECT_THAT(EcdsaSignBoringSsl::New(key).status(),
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
