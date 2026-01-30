// Copyright 2024 Google LLC
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

#include "tink/signature/internal/ml_dsa_verify_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/key_creators.h"
#include "tink/signature/internal/ml_dsa_sign_boringssl.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

using MlDsaVerifyBoringSslTest = TestWithParam<MlDsaParameters::Instance>;

INSTANTIATE_TEST_SUITE_P(MlDsaVerifyBoringSslTestSuite,
                         MlDsaVerifyBoringSslTest,
                         Values(MlDsaParameters::Instance::kMlDsa65,
                                MlDsaParameters::Instance::kMlDsa87));

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithContextTooLongFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  std::string long_context(255 + 1, 'a');

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         long_context);
  EXPECT_THAT(verifier, StatusIs(absl::StatusCode::kInternal));
}

TEST_P(MlDsaVerifyBoringSslTest, BasicSignVerifyRawWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(MlDsaVerifyBoringSslTest, BasicSignVerifyWithContextRawWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(**private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(MlDsaVerifyBoringSslTest, BasicSignVerifyTinkWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(MlDsaVerifyBoringSslTest, BasicSignVerifyWithContextTinkWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(**private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithWrongSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify with an invalid signature.
  absl::string_view message = "message to be signed";
  EXPECT_THAT((*verifier)->Verify("wrong_signature", message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("incorrect signature length for ML-DSA")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithContextWithWrongSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  // Verify with an invalid signature.
  absl::string_view message = "message to be signed";
  EXPECT_THAT((*verifier)->Verify("wrong_signature", message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("incorrect signature length for ML-DSA")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithModifiedSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the signature.
  (*signature)[10] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithContextWithModifiedSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(**private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the signature.
  (*signature)[10] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithModifiedOutputPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the output prefix.
  (*signature)[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid output prefix")));
}

TEST_P(MlDsaVerifyBoringSslTest,
       VerifyWithContextWithModifiedOutputPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(**private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the output prefix.
  (*signature)[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid output prefix")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithWrongMessageFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(**private_key);
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST_P(MlDsaVerifyBoringSslTest, VerifyWithContextWithWrongMessageFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(**private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  absl::string_view message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST_P(MlDsaVerifyBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  EXPECT_THAT(NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey()).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_P(MlDsaVerifyBoringSslTest, FipsModeWithContext) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  EXPECT_THAT(NewMlDsaVerifyWithContextBoringSsl((*private_key)->GetPublicKey(),
                                                 "some context")
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

// Test vector based on the ML-DSA-65 standard.
//
// Generated with the latest available KAT code
// (https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/)
// adjusted to the final standard, using the following parameters:
// - DRBG seed (count = 0):
// "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
// - message:
// "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8"
// - context: empty
// - pre-hashing: none
constexpr absl::string_view kHexPublicKey65 =
    "1483236FC9F943D98417809E95405384530ED83E151E8465D34E4638F1F8D7058D62E19A"
    "B806490883A823176D4DC8A3C10C9960D0E948A9F7B62CA8E118DE5D7A05BB18E8018B6C"
    "ACB4FE7885490599939D90D004BD480B116F5D6627B6C4C1B2A1496CC3525EF9F19953EC"
    "63CDD6EBDB21D65B27C644194916AAD07CC559B08CFC1282D25D7276C9E5062E0B1C4CF1"
    "11C0A9DCC49BF40F5ED3C27CB4E78E39C1F068736A788E2ED4A02E9EF23EACE802CD295B"
    "6EB97D533091B3293D9BAD2938DFDECF2C4F9F6387B38A7FD22738A010B85949688650B6"
    "F063B6BC6350A1E84C869FB3BBCDC4BF6C0D0674D7C07F7AE78E4BBB302B6DB8488B5F91"
    "64E5E264682E45E71B58FC19ADF5EA892439EB352AFDDB63D22177AEF17261909E3F87BC"
    "C7E1B1A58CD5DE8F8A886A12D7137CE5BFBD2C53ECEBFD1B9F2298583D767E0DB5178B95"
    "2F4D069D66FDEDCA1FBDCF8720AAAA5313C0500ECF95B9B70E7E3D58DD2B57433D3A0637"
    "DF36E964B21F44F791B3AF9074D6DBC9A2FC041D9E22D5E387C4081E6D4CCE6AB11FC8B4"
    "F2C718EB2A19924E3F17EA1F44D0084B5D5296A97A3624E4E1F6CA05229F2888557AAB57"
    "7FD72F8DC328F0E4F45DD13A191920F671ACE3BC29DC3195E951D0F5EEAA095A3D5F20E4"
    "E4EA1AC157261C1C514AEB6940E63053AD68383F14E923602E6B241E9813246B47F009DB"
    "446FBF61246BAD7ED386647D020A854CCA39ECAE5FA6D667CB6D433F02BC2FAB9F37096F"
    "3C127741EC02A46C81022E070AE1DF54623DF44C5C744EDD0D3BC66581B8E1348E75B5C5"
    "2D0E41BC71EDAD5B12DDA2280724B7D704BFF2AF04505F65AE496DA86701D36BC9AFB0B1"
    "99442A9C5C743D97880E89C8CCB34C51890602627924316E79D4415CC1C2ED490A7A6EBB"
    "4B507181CFF18BB53A6B8F816C15A2EA8667CE59EDBE8F42376001E31981310CA403E083"
    "28AA97828DC3A86C260819BC8DF72A3E29657CA65B7763A54067958CCD6FD73DF789B306"
    "A37185C8117F0C86CF9D1C48D102ECA8343F41F86F6084E2E72E6952357D7DC076A02A7C"
    "EF64724AE634E35712E291A24704D2939717246371B42C11A672FE8FD31DA83FC3D5DE65"
    "0FB2136A13A0D6229A115EA3758E3AD0810A99944275FA8FECFD2BF1D130B40473F4ABF8"
    "86485A1E36290DB437B331DB303539F98D298183509D934F1A747AF29BC36BD7CA79E5D4"
    "0D098EBFE61F400620B5B1AFB81327342AADEC634F1A77DAE793D55A252D391AD155A615"
    "0AB049CBA0270F07936AC21575BE6FAD53A0DC23F462E377F2C882391BAC1C17C11D18A6"
    "77C3EFFACC4C6A920596F8654BB4955750BCBC18744375656F0B594D825872BB161A1B7F"
    "DFE7D01E7A19E02F41AB9D02D1FED47161716172B8D68DB04E57C74053DAC785E9245BCC"
    "8DCA48C736457EDEB8A075C1C42254E87110CBE4A909421AE6AECECE5D65834739BE6CAC"
    "51D1023CA25C322B7B3461EC65168CCCF483A2668FB4527BCB312564C4097224DBC38AB3"
    "97C3A7FD693B29992B9A773C43C0E9E94479F1762C91C367D9A079B13FDC38BD74F209E4"
    "D543ABF8C9B14CED015599DFAE94723361ACBF6C1C0434DC0EFAF22C61057775F17F36D7"
    "6FD75D6BFCE7DCE922DCD7585AA33CAE7A6916C4E4AC5F86E4753F8CC798C20205C8C476"
    "56FBAD7799B6A53DAE5DCB74CDB677FFFA66CBF2873A219413714578D6DA3B61AA29C494"
    "C2F084BE1FA1C1CC40D1E4A424A4CEC73E455062B6E28C333839570D6FC6C08402A8D39F"
    "145B97C3AACC6F24702E80F66F5D2FA1530CFF2A07486B3D38D8C9994EE633C2E527AF49"
    "FBE26F634C6663CF95520E04A76F33E8876826B88887C4FE8FDEB1C50F55C7E7FBC2A507"
    "7FA029DB53B7CD8FA3576BBC219AE7D7B21518FD94FA187D39D63187BF9F2BF2592F1A7A"
    "35628137D82E50477FF3406DABFE558A3FD30D4E72D1F523EBF51DF6C7BFD9C85325897A"
    "7949113F30C9570F3A9FBAF73658430C3B2AFA43BF9D37D5410B5E416C5CF375CF9ADDCE"
    "CF560E7D636C2D58B89D3E5A446201990EFFC467FFBA1009EE90D0F46BD2D7018AE92CAB"
    "ECF62130BD7B4A077AF31882A713C73572387533EA249C9A18F0599C06EE216CFC60F749"
    "8B2A75F3F8143D90A4ABF8651DEFAD600FD332AB09E3D8FAEFA2EC9152EAF6F2BE6B7862"
    "9022C0231849BE4C13FA08B827EC301150FA380663F737418C8BF0700F4327F58C2256F8"
    "BA8B61176DFD1ACE6A81C19033E3D678A9CB234F85A5B6372EAF1A1883F5ACED3ADF58B7"
    "FABFE44D986DBEDA351EA9DE5A841CD523336F986AB8FBBECF1F52B1E87DBB3AC457A743"
    "FAE899A5BB3D10EAFC4D0808B7FA98C8068093CAE7A0BC2074BAA701273734C28E97CD11"
    "02FFBCEBB83EBB17C9200BE6DBE58BC87C522E4D24254204FD2EC52C60C1225649C3DEE1"
    "7012C1CC0D5CDA0B2F0FC4F27274E04ACEDE68BACE92E294B589BE45D74C5377AFEAC718"
    "2F4B702B5A50B49F1B32BD476483957C664676A819FE6851F07768DA82261C75D53F8F04"
    "A64291A56E008B11AE09EE73923257EC195020D958F7B6D43ABA268978CB33B150A9C0DE"
    "CAFBB36291257512CC7F2CB0B5564A0F81EF4686838CDBFE10475520E6EF69047CCA864E"
    "50C86E9D91FC4EAE741D4BE8AD7B12952B76C3429548169C370A7A5E2DB3FC809B993095"
    "2EF5AF9CDCCAF74FC13D0DB8D55862858E47E4C6F66FDA9DA423B884DB6ED79D012587F7"
    "57F0BD974680AD8E";
constexpr absl::string_view kHexPrivateSeed65 =
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
constexpr absl::string_view kHexMessage65 =
    "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";
constexpr absl::string_view kHexSignatureWithTinkPrefix65 =
    "0141424344BD0D51DB2F225AC6D3DA8F0C2439B0BCDA26EFF7EFA67CFD3C2B98EFA08477"
    "A74088DC638126865E493697B6FE360FF9C55B304D15A7474C983C3D8A4E1AB28FF9925C"
    "C9073AD986D4B53C28B4CC909DC36B9334CC4510AFFDEA9548620923ED2158224AC5CA8F"
    "EF19228DBBBF12956F5422176E8A474AFBE6EC6551F1FFDE71E86C48B39BE6CA540DBD78"
    "B985E89A2F7576325E79DCF801585D30DCB3F971C827F4489745D450DF7AE34496C42C7A"
    "8778AAC7FDDB9740CD3F07A8AFAD1C1471FB9591BBCF37BEAEA10C465ADB4BD7303ED6CA"
    "41AD4848CE8A5659F7E3D4894AB0E79A0E7206C9FE278AC9CF1F6A3DA6B9FA8E03AFEEE7"
    "17739CBFEB5C26EF3B1C9130C8DD46F9C8E8149DA9B0FE5AA8FD03600F87824A6F2EE8BB"
    "CA0EF6D8C38EC526E982100BB8A8974EA91129BF827FE4CCA13D7203D38AC51B2A140259"
    "48E5AC0F71394EB804C885521EE65EEA303CE30D0FA9626A914F36246A8F55EB2D866B21"
    "5FC191CB734CC6B4724C8C1562F81E3678D39097871249B86833C6981FF45CEC71339E1C"
    "6F38ED1D04B6C70C21642D268B5E058F8095101C2339EE5619280F2553308DBCFEF74537"
    "DD02722E42608FFCA2E8EA8B8A2FECF46948C952D003071792845A07DBCFCC483B594CA9"
    "E0A69664498835DA427761E19F9FDF29E5319AA0FBAA7150DE0B1F951D9CC0E1B62DFB08"
    "57DB7C2129A896D65DCE0ECD3A87FABCC2A4A6FA5811CF6312DC9E3ABFD5ACC116A8A25F"
    "45AD3736FDB541276732DCD997B1B687BDAC9827A4582B8D3F0877595830E2079DCE9104"
    "E1FCFEFD0F8225BA9739C30CA7671A05688B55BCA1F9ED968E6F3F2831E3D54E596707BF"
    "63FD6AA809FE410EC38A17E3F8DE2E050A9E6B81CC386CC229041A7BE15FFC912FC4066A"
    "4D2D7FB98AF7022840E593C4E599D0309F37B65B85F10541683300779FA41124B19D4032"
    "CF8D7AF5726D3A08331D7A712DA910903C0A381F616CE5B1085F779486172EA4D7B12769"
    "2557DD156B63B0E445ED8888E446397542E50C9BFE7B728E31388F7743D0F51151D4B4CB"
    "7642431ED0BAEAE264F4B2D9BAC2D5618338EE092228A251A4F99D4F95D263CAE16FB9A4"
    "5A51D45BEF0F6CAD30547AB4BAA1C6F28E6FF35B195D938514F58FC2B47BEB8C895D213F"
    "11035E5FAEF85C917D7AA551FDF8D316CC4DE5A159CD4F39E3C118673984147C82BB4108"
    "9CF0D9B6712E899A99CBA5DE33BF33E2C0DA03745031A48A37F7E6A7288790839461F2C5"
    "8BB5ED93477834B572DCE2DD00DD31B866C2387076037053872D8CF8EB57AE81FDD84823"
    "DC69FE0A33F599846620AB74E86912759E245332EECFEFAAB9726F8A59256200BE72BC47"
    "DC3E0A4E28868842935D216334191F32E0630920D8DB05EE62813218A1E1FC5DE96719D0"
    "8A00FE7D5072C8D51B3ED0AB0F9D5B45BBC2D5DD2CC7E6ECCB080D617565119C4B2A4E40"
    "8A0B18EC969DCDB2BB7D8DE2EEEF3A76A0A5E437C6681AE7A00D54868E0F51EE39616AA2"
    "9FEB7ABF4A3E17865003B781497BA572EDE6EA7A9479FD15C295B79C0384D4D8451043C6"
    "F67F2E10D8442F0C4E72684D6576FD41BC3756B1A8834082144760C7F609B3665C03F001"
    "073CCFEC1EB18FB9A61D82A8462D0A86FF80520053C55F2D79502F95EEE9B50F1B95179B"
    "EAB6EB1ADC4F582A9CA12C31E6F165E064AA9F289DD2A5E12F45E71C98CBC87DBF218926"
    "250D1A78DFD2B46B1DB4844AC63C5A6960F67A6BF0B270337E629AC04BA47883E52C3324"
    "6863EB9F54BF2DFA5905F057490FE14F993D81EAC50E0D16DD0EB2098D0D1170FBF30892"
    "A7BFB45F6C6B7E349865CF4313D1572CA41A06C0D5561B0704AF4BCD4CBFF4045C5F76A9"
    "A760751F7B1432F8049CC9C0496F3E80026E2078CDC7BF54132C84200A4C27B23AAF69E9"
    "7B25D8CBADA6F5C82748D73F8CEE44980B909EB0C11EB49FCEA972552BF5BE540DD9467E"
    "C81D70990562DC558C00CFF68DB80F3D2BBE61D7E154A2D5A4166E86546D8A82886E1CFA"
    "28CE2D8BF57D67D9B6CE32D451F9B2B4D73474C299C64FDD8D2AE15EAFC3F88179B8B364"
    "FE16B51E7B6C4DB47D796E159546BD409DD72879234578875C7940E057FB9508DDD9754D"
    "130F5CC3E32D82104DBCE1BA883FBC0C9AB9072A1A2771B0EA1152682D182D537EEEABE3"
    "F79C531A26E236AEF6479D5A7817D00723D0183E4A1A671C3285BAE7793D7FF982A6B90F"
    "7D38E40F763EDC401F2BD0618D3E305257CFADD3CCFED8DD3FD03CDBB533976FA353ABE7"
    "3503EF8360964C2CA78888B4E67B0EEA68D35E64A840D136A7F0CA41CBBC52543BE45CA8"
    "46F0213EEA90D932AB3A6902795B0B4FAC28C838224309E94782FA315BFBB9A535F3763F"
    "A9C3C95FFA3FFDA9C486678F7905A3637605A6929F234B9B04BDC729E14581888848930D"
    "F0D77FB1DB65D75F292E0EC78FFF3352ECF99D87E0B6FFC78F5B9CB423FCCE606D74D35D"
    "115A418EEEAE012026691B82D5B0262A1DD137ABF192683173A5615A3298A2224280C405"
    "EEE6094ADD0E1ACEE74204BC0F8170221621A71743084A072FDF03293D8FD7778E8E3282"
    "DC49A1A950404CE827C281E1F57E9DFA1F1156726DFCA3560F5C909987D6D79E83116615"
    "5D5AAEE8F1ED382863195ED48EA6924D7A119EA99756434092F08E217804EB4943E56A42"
    "CC7AC5CDFA7CACE562FAC86AAF3BB5C3CF6F6DC35036B388E9EC8BE2272C2D6CA425FF23"
    "E6EF7878332042B120246271B93F87C463434921D0BF6A105A2C7E473B3C5E4BC5828403"
    "C130005B2EEDB7C161010A7A782AF3EA91700A7610DDA532DAC61DCA768B51541D2F6213"
    "B9C5047CA2AC0E1DDA275EFB58359B5AE203706BBCB1B2DB3ED8896C3721B51865A6F9B4"
    "B8949FAB4F3301AE7CBDC540F0B04FD6E27BE48748DA228DAE22353DA7CA1C464E70FB78"
    "960491279E827128BEF241C764061A5AD103EE62B26AE08066C5F20B807883C8E8A3144B"
    "7968F232627440154FED536DCC09DC9E33BB7BCDAED850F0435E1B9D943F79640BA06F21"
    "F99A1D89997BC5529D1E69095DE36958B8F186C12007DAF19115B0F971DFACB126280E1C"
    "4B956C458F9AD2EDF2226A696685A3DEACE620DBAD643B4B2E31911F53BBCC1E712B83DE"
    "8687D4956EBE1A30CF4D7E86DBE8B6E28DD6AF59BF6E83E25D9B67458ABE922181C4BFA5"
    "E5D047A7799D8F117411DA633096CE2ABF19C5317C545835B06A54759497605A0265A039"
    "6C4F069F7AAF9E677140679A265893780B0F4ACA2E48010346CDA16356E6D69F48FBD6E9"
    "763E1EAF576008BD2EDCCA2DF8808989D801F687EFC97EBD1C0FAA8555664BDD49E39B38"
    "565480D7DE0BB51E1CC5341DBF12DA73B5AA7DF954B5569272A7A3EA3AD45D8F65F71800"
    "7A0C35AE3C7206E14AE7033E4DCE999F232BBB488AEFF090A1D160B10847B134FA828671"
    "14C4EFB7CC83DF601108E61457F7242FB159B0840D7711C0C50DEDBDDF346BFBA7C7EFCA"
    "4068B35B93FF81054115AE59DE3C55BBA020AD66893B88AE491F8F6BD45BDB0D506D15E0"
    "50B26BDD0242F0EEC3092830E3F35D59A4B94B7A41A993F44DF9199EE6B084681D554AFD"
    "3970DD410E748F4A95F3F5A3B2827F1C587B563FF7F0D7C47AF3B9F72B8AD6A46C2CB178"
    "929F80C1852AD8247769BD4FEE274A0A07B20137CA67674E91779D9C6424F06E78A8BAC8"
    "07C31CBB4677E9CC7D8755997BD19DBF053F1EB7DD6DC3875E667088B0501FDDBAB90C6A"
    "4C215E28B17DB87B0F4423C6108813AC993F69CD20953E0C6B85E308F20F1855F5993FB2"
    "69159F2EE5D87316A0B744CD6530BFAF581C7FBAFD20689B702BDD4F907CD9D5ED768FAB"
    "06CD625B171D7159112E2446F8B6B2FD3B89F43D6C42B5120CFC98AE2762D241C41D32DF"
    "F80F7147119FBA9900689E1919EAD74C77F27C046B513FE143884A439F1E8399CF97C7E8"
    "3F3BA585C5A0117251EFB5AFF33974D5B0FDBD61B62CA5692983643788AC31010E70E690"
    "9BE8757F6BD2E721BAC6790F8DCA7D1AFCDA291F1DA1669E8906F4880E0E1BDC2608A0DF"
    "671BA401C178A53AA6E1B2D6C90D2769E4230B60E9FF10EE38A1532090B3D5076D1D3206"
    "97F4AC06FC8574136373FDF90D6872190E26F5311BAF686A95F47EF7A31F8A6AAF0196D3"
    "CCED25D5A549FE618D02F3C531FECF1C6770BE5B43FFC299519B7AA701BED350A09AF45B"
    "9268D8D5D81E8B962303C1F8E4BF15F5DE14A85312EB1C9511DF3E687CA14081754A2958"
    "324B4E5BAC035C91240F01D7719DAAE546ED56885F1F393DF95690C20618AAE3229C6488"
    "AF7820C3E8B421957CCF4F31A5173B7282FB972F7981AE53F73F2AE5747B608FB05F0188"
    "8E80C1C6CA031D52E573FBCDF986471D038EE3C6E0814E24E8DF75BDBAE63F2909B47D94"
    "01107439A6B022C897763194687110D50779A9ACA6231B04D587A87CAADE5E4E91B7BCF4"
    "3B2E469F52DBF19AB1D180F477D5DF2E45ED2609638E22E4F5143BB0E733F16AD183153C"
    "8460E9D0A821C9AE4AD7DB358B18E91A9022A26283F553D722F4D37B3B9EA7E5F684A139"
    "5C72EAF26150960A318B8901630E1A657479A2B1F7181A1C215678F3626BB7E2FD0F3649"
    "8497A20F2D3C467E803F697DA800000000000000000000000000000000000000080F141A"
    "2024";

TEST(MlDsaVerifyBoringSslTest, TestVectorSignVerify65) {
  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = HexDecodeOrDie(kHexPublicKey65);
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *key_parameters, public_key_bytes, /*id_requirement=*/0x41424344,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_seed_bytes = HexDecodeOrDie(kHexPrivateSeed65);
  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message_bytes = HexDecodeOrDie(kHexMessage65);
  absl::StatusOr<std::string> signature = (*signer)->Sign(message_bytes);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message_bytes), IsOk());

  std::string signature_bytes = HexDecodeOrDie(kHexSignatureWithTinkPrefix65);
  EXPECT_THAT((*verifier)->Verify(signature_bytes, message_bytes), IsOk());
}

// Generated using BoringSSL using the previously defined ML-DSA-65 test vector.
// context: "some context"
constexpr absl::string_view kHexSignatureWithContextWithTinkPrefix65 =
    "0141424344a7ebad8e6ec0a10088515da781f97914ce363c3eefa1ba00bf01622a9dd80f98"
    "2f285c64a99465f9fae30f874d51fca777c08ee2e31c37390a24a92bf286c38539952ef859"
    "176939993e9ee28738a14ca5a32d12b3741c4ed7b95addc68428d548bd67bb4aeafff4d217"
    "362455cd1114058b6f517169527a63d4aa7d95755441867b49b2ac2cf8e8ba0ae5d9a6b2c3"
    "3448800c389a4f0e213419ed4500aef3b405205c748c49a6a9aa452a94a64e7b76b1e4deac"
    "ea99856802d8bd9ab268ef9d115fc3a96e24179b1a4a218e5f23d09cc436c1334f5f9d2132"
    "0c01f4196ff7a8ddcc4c2d9b8581490d31bfddcdbc4a6de13538168a2d9af4282234dbef18"
    "cc3141f995c13e5e892eadcd6d26df0da07a4e6367f77b48db181da20edab6acadb9da3684"
    "27c064720247bd0b828ee2a5a2bb03e635fc36ec8d8086b51b80a9190f401dab81c554d075"
    "f29d923a28116f83dd79e76a1c78b535bbe5395e00af757e5a907c5e05b2c0becb2f182149"
    "0db4000af7b73f4b059bb4e7865fb2f05c2f45ce9986d9e3a2c68a59180648ec288751b9e4"
    "076a0ff1b2f2a7cbe45b205a5d9f183504bad36d00e2704c9db81f1750c03f4307ddf5c0f0"
    "f4d62336d6430645c11b9eabe1595bffc44653d81fba61e67ceb25f5466937ab40dacd6a8f"
    "65cc2eeb289df996e331e9a60ee8609ace08d254e5b0ceae966af04703d63b533fe1b308d9"
    "841abe55020a3b1cc90d99e439aa8655d41098c81f15da6396061dade0b0204a1821a45a44"
    "5db578f661b0a50002251b7e8748860bbb8972e381ee60735f046e6206471bbcc8dee4825c"
    "fd3c631ac389d74b3a8b657e15d6ac1d2a44ddada62b5d622c20b02a5c7a079a0e3dea8ea5"
    "f96d86ea17a16fd732505454bb24c442270eeba833e8a07f09a3854a0a7bd9168954489ca4"
    "0e84a3d5372be0baa9aa301974fb962c95699d2bebee2ce39d9fbd3b1d9e83ab1ba754e4d9"
    "f86f41526cadc90fabedf30048dd62e6cd34a87a88a6aa805f1f6ccaf6a3a65284d187c6b6"
    "6543118b9767ccffc12789f0238ccc88ac908b18f0d5b9f193fe3be21a8954b35e7dbad1a0"
    "06ac49ff0a13dc913ad0a69129bd608f25a372871511ab89136aa8f22e7a740e5188f344a8"
    "6087a24dad50f8c15fc8caffb1c74eb9bb26e03f6ea9969bba4042f327b15301ff01b5f86a"
    "33b0f6470a8178fb509e4ca4362b870b49526564171217d375b841bf4ba4dab24bdf6d945f"
    "4d71c2531f4c7939b74abe6993f40e8aca96991e2ec4e709a3b9009f3f70888c151d7b13bc"
    "b20822d5547c374045207d553bc7b3751b2d6dd88e36c6aa22ebee6234b37bb864dab6e9fb"
    "2905c93bc5b7fa69f78cfe571200b3bd89eefd7353c3bd4af68088b72999f71df69bdb0494"
    "01caffbf644fda6346f9f163abb1e780a31c7f6ed8c2e91fda0a1acdb43ec83d600554fd6e"
    "025e2ea4eaa84498812cfd93c5a2bfb9b50e338bd7fde130854764238911896643ee996657"
    "338bf0a96b35adfde23cc8f42063e22100cc772531b9d7f3ae70256935bb5935769681c9d8"
    "adf5d8e6411574f497be55b11b3c2260df04c1a1cec7986dbdd36202d8dec5a42588a57e28"
    "148eacf68c5e8d3526b7540f6fd585969ca6189bafdf9627897173010e38abd341f89da888"
    "b5d8889c3c5145c506ed4003a7d85a6986fb395df120669e8b745730e6e5080bad4ad0e9fa"
    "9826f48d29896add81adeb70ed88cd6fc19a3243f00b1a7bf11d499640715818e51b231420"
    "d9efe38375f9b8b65b3ab377e4854dbece0ff7fd235311d292a8f4ff0754e82bbd0fe48d34"
    "b211954bc846bcdc01eac8baeffe96c1cbcfcd057e61289265512b2ca56c82912cbbb8fecf"
    "6603e9ff376e5ebbc5e74e0a4e73de059e40fbab41387106d5d396696a41f96b59e269f65d"
    "117e60dcec86968372bf7997e4f8a7bec47499478f9995df69753fcfa6737ba88f9ad5d67a"
    "bc3109100f0db50f233479d990db79ecb5ad989f3f13ab00b1b1581cdebd76567adbde6723"
    "8d666b80f77d094b70af774fa1bff9caab74327b974a2c164f12bb63254de009766c1406fc"
    "d781060c35558a9edb2e6d02b07376067178b8ea7409df11d7390e58c3850a0908bcc88032"
    "d208c75142e83359651bf07550e426a00c9a06bfcce8c1d3c89125b3417985465ae4000996"
    "bfddee62e05150672abc8caeffc5f1b3362272ab44a132cacf06fec146133a7108745de0d5"
    "fc6e200af58a34221e21de6d25f0be70f8f5e36284f4a05ca0e8d66cb58e99cf8327af2041"
    "a9b3e794f7d1cd186b82f04db401d69337f39eaec8cf2a46691d88215d72e34c1a11f54ec4"
    "53c3b82255568890a98e106d27b5d83c3876aedc5ab0b38ed8ddf1a99f06010ce23abe0225"
    "2f7b44b39fb91f79f91a6e9417ddea29f4b987b684120882731e28981b8e1b796dc40447b2"
    "d95e34b3b793a14699c7c67c3683af2bbdfc1c70d6fc503e7f24b9fac693dd34cf44e08c93"
    "41f53ab158e9d23b3fdfd02e1ab5a90b0f4f3e79fe28bb4d31f6e7369a726345f2b1cf9a93"
    "2f13d94aa4303d2469da39e0aa627221895f91a275813040d1713e62ee734ab8ddc29e5665"
    "8bcfef9b36e090777129db7390d31882d72595fce6aecefe5b58b9dfecbcb040bb2668f953"
    "32b9f84ce115820e0a9c26c68acfb4872bc3841f0d2187d7147d5395ee7f447f2b49577c0b"
    "8c16d35a95e2d57d666dc89adfb8e63624289f52b743f6713b39eb2ccbdb2990ee497c9552"
    "b55d9c4399cbea81386bfcdc84461460b05505fecc9d07778267bc26160f6eabb3e7395a28"
    "99702e7a08de81e99c8048b8d54e0ac7f42345b8a763430f2630ca418c5ededac6ad4cc50e"
    "69dc4c81e28818602f1c33c454f6d0e5fb2aea11cda01897a86881560d02ca571cdade9bea"
    "1cf37389842ddf8884eb96925480093f3abd11daa02a284df63b893492ed56e4508a195212"
    "f79a0a36290f6cd264e1ca32fbcd6d7fdb07b377d4bd9d9403050e32f25e8905fa7e32575c"
    "5921822183916934627bd0d7b052cfb02178b193d61d8d1ce496ba1b88804b8576714d21a9"
    "9268a86fdaf3612db6813c452b19198627c1026f05af7f0c11b947edd33f10e64060c68f8e"
    "2f91e4cb859b15d447da5d926a0cea580fe1c652fe3ad24bd8f0980d399473cc005fb19958"
    "2268ee114439a224d0dcbb90c7b44cabac98bc596e72b06b9d25e2222ab52a4ef1c1e18b97"
    "5ddba1d884fead7843c11d18191af85e59cf71e37d35738592704082e2d1841b77edda7841"
    "298487025dd0d9c9dc90127b969634f28fdd422a804ed6bf18f718cd9951d761bea1f415b4"
    "1035628055e46cdc4c8ae709b14dceb08d359c8d968d5783f9980efde13d2b2e13eadc6bd4"
    "a7e601dbded044a1476a8c5c2de9393bec981881decf7481ed2b906480ff332ad2216da45d"
    "4a22798db2e03d1deaceb5f6d204d5e15d9aba79c074801f93a990221ec273b28fcbd19df9"
    "071117b219aeda0ff809d62b2c081672e6bacc57cced92c9c7eea6b5d3bf97cac8e29d3376"
    "d9a4b762b37735952828ea388c485a08aa92e1660ceb7be2ed7baeb99e3e518865d93b8091"
    "7b55dba62a49b6bcfe89657160ad0b10dd4713db4f5ce3dc487a66dd78efeade72f184e686"
    "0a3e4c6a0411665f27a50570d6f950c2ef0c9a5a256bb467e3f047be81057660d705a00a71"
    "cafeb86d4f544dbe4a7a3bb7797935e382415cc577e43c5846d0b28545f1c2f45ce4d92d75"
    "02edaac2a63495a086a9a2dec03cfda0fddb70f008777614beac73bf21d971e9b2921698f3"
    "f10bf17a65fb69421b9c61cb041ab7ca96b0cb3db0bf9010e7bb85ffc3a3fdad1916cbcbdf"
    "c7b3a60a7246c9099363bd2f7b4174684a7799ac4368e45465941df18461e956dcb196a0b6"
    "ffec53ce7ac576cbda24452f8c3aa8a1d6160556eb4b02de9792c7a89e11502b4decb72141"
    "fdc6d1bfae8e8e1b34c5a833c50c34fb2bf6e796a63bed92b6bc9c828379e2f23dd5870d95"
    "f0e96f8f8e3723759dbba3840a359b3bb9bddde45c351ecc741bc03804107e6ad8f49dda0b"
    "1d6692af817323a0e9d999cf12a118b904a7c368717db4f492951418a4f9b4f09d40fe4a94"
    "801e326aa95c8e2d6f3517060ce819dc0919f255cbe7bd142f1b41a30b3b2c8bb9cfc46d25"
    "7b6b00eca996e9ec0a38dbf99def22edbf92e80f47c561f188dd692e62b3391440a7c87294"
    "d007799023c3a49ac1567b795a6c08e725479c217fb69d5d07c3c07711ecc6c7c32f776ceb"
    "2a1deeed0278705d39ab82ec3fc964058694786692da19280ded12364867aa4ca805414f06"
    "3e3bf90c830d121d58c79a47509765c23c0aec5f821702f30a4229819ee7b0c167acc11c65"
    "3f26fd7a0efaf10c5632ad5e5bb4230726320b976597fbc8d15af78d02d86fd04b19be3cba"
    "9ffe42c1579bd842817ee71de65825eaedbb08924e6fc730b35d4df449cc702188b6a50300"
    "6d1225d2a157576c21523a061c8eb2f91afa5598f0daa5bfb869d96385d717e35d870dd5c5"
    "36af3f04d074ef26b228a628dcec402809650e37baefaa46231906988e3c93d9ab3d0371fd"
    "1e27372c93cbfa589dace54350526768747c999dafc92354568beb00000000000000000000"
    "00000000000000000000000000000003060a0e191e";

TEST(MlDsaVerifyBoringSslTest, TestVectorSignVerifyWithContext65) {
  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = HexDecodeOrDie(kHexPublicKey65);
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *key_parameters, public_key_bytes, /*id_requirement=*/0x41424344,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_seed_bytes = HexDecodeOrDie(kHexPrivateSeed65);
  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(*private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl(private_key->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  std::string message_bytes = HexDecodeOrDie(kHexMessage65);
  absl::StatusOr<std::string> signature = (*signer)->Sign(message_bytes);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message_bytes), IsOk());

  std::string signature_bytes =
      HexDecodeOrDie(kHexSignatureWithContextWithTinkPrefix65);
  EXPECT_THAT((*verifier)->Verify(signature_bytes, message_bytes), IsOk());
}

// Test vector based on the ML-DSA-87 standard.
//
// Generated with the latest available KAT code
// (https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/)
// adjusted to the final standard, using the following parameters:
// - DRBG seed (count = 0):
// "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
// - message:
// "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8"
// - context: empty
// - pre-hashing: none
constexpr absl::string_view kHexPublicKey87 =
    "903EFBF16CD1F779825106F76DE12DF49CA4371B57117480702A1D94DD9C2042BDDA0535"
    "9144230762A55D09AAF6961245E21B0D413DC2F39CF995327C6A1D52607BD9C3ADDF70D0"
    "56361D8EB86C4B60FB7E0DE5638E4255454CD32EB48653F6A9047247233284953DA6D5F6"
    "5AF1B59421673F6F9E89B58D483C6A9D3FC4EAC36CC3E489CA243F17DBCF0686B8B4DCC4"
    "A37078B7A8B28218777C5C223ABA3123EAACD83CE2ED91ADA7EE0EFA23179F4457903417"
    "EDA5350C4F4BD856DE0BC419C91B76E7DE9074C8EB4434D6055D80AC55BA276427FE3C84"
    "4EC42BBD37EBC6CB142C6C1755F02F7F0C94631C987EC447060898B578144950E77CC51D"
    "9797DF07025C8393ECB565C32EADD3179C696CB6AB5DE99B8FCB623E8C59D836AE3D4E87"
    "9CFF4C4849880F0FBB293E7E637D3897D47CAA894656D58434244593D72A9781FF045A40"
    "5F9C8886D1C2B828467A9BC28C4E29AECE6536ABF539B02AB03C876D899376CCDDA5C1AB"
    "C4D3B2AAF3C5B3C7AD1956FCDB37F691E3E3DBB43EA967E733EC9E2D06D5A0E9FD67AF30"
    "20CBAE5FCD7490E44F5E2646245FB1B92C93BFD6945093246D490A1A0FCDDD6D46BC4FA1"
    "1137AA673D562488FA72CFB7FD210D3B3F04794415826861E87C50FD9B297F0EBE32153B"
    "959D2BA684AA978827BEBF6B825C8C283388DE6237BA4B51A0D47F01C57951809B9592C9"
    "35C9ACD64F45D08D5207BA365CA2AF7908C7791A4ECB8C20EFDED66EA640860293542479"
    "7912E1363CB725C42DEEC98730FA99F17AF4DBAA825159164878F5B97FFB8959160EF304"
    "E5E1A10D7F8671454B81081D7E24A75922EAAC49DD67C0CAAC7E24D3F914ED64FE618E26"
    "860C6BE09A6BA56100687B3F0A61EAD9D55C984107B1DB88A1901ABFB93B0C3556E4A360"
    "1E08BAE9BABAFB177D61702E0E8A357A2E760EDD39CF7A3C601C022C629607BEA771E408"
    "BED8C96788200F16F3F76F9FB89B4F04389D40B76FF720CE478BACD77E659359D3803BAE"
    "4BE439FD4A212B38E169BC1A1CF9594FEDF4A33ED7DA7B3E1D853D055D45C85B817805D2"
    "5B59B52879B1EB7D59B723D05AFBF9F62FB1384A12748B0965FEAF5CCC5F45162F173836"
    "D87B25907C262AA247C198E7EDFE7A472BC6553843E14C39E70DC993E566F0C339108FDF"
    "32A7C9C9186A09BD5773B3D3393CAF8F8D3CCC2EDB7BA08FFA76C918669560CC170F69CA"
    "41614ABFE6D230AC167A8F74F6664A23179580796EC0C01269BA2FEF895B36EC666E750D"
    "CE0F76BB411867EC5152EF5B1A1AE2A857D791147EC9BF50D4B1E93562812787C7CD07B8"
    "ED8CCBC294EC0721775C69731B3B471BA1621CD5BDFD11D5CA1D38EAD2A5B565D617A84D"
    "08FF1F4AD5BEE0470D09B67C8D24C9018EB13205E6C86049B50C5DE2C52345E015732CF2"
    "CE1DA9E5DF6CF0F54256B4D1D35E7193AFAACF616E28E761D977ABF2A54A3FE5D2823A27"
    "5DCA6360394F0A7879AB61871BB8F15C9BF1D8990DD256FB7F07C90541FB2AF3C264E24C"
    "8DC24BA47F6E23C9C17BA3162CCE979C063A47841A3D264CB8489082B3B1266539ABF7BB"
    "6D6C277064980799793656E1F56906BA4541C19A8969CAE9FB98EE76500A895DF493FA7A"
    "A4D8C4CF2F6AC554AEE05490C1CC888A8D9F30F477EF76DDC191794F0E92D3FEADE9B09B"
    "1DE64ED0EBA2BFC82D6BFC693A48205310D32BDDBDD48333AC81DB32B404163E6A835A5D"
    "CC3308AA0936F39E66CFD9173437B00BAE28D6D4DEFC2DDAD001E2A6E782BDEFAB164A21"
    "4F36E95C307CA141A1F38D5EFA943779E9D01A72100F5DE76A072074286B5C6739B805EE"
    "EFBA5639F2EE0880265ED091E4A2DEC230CF7453F4BDEC313E16297338A3E3F6E03C8FB1"
    "208909A46DAD667D14BCB66F9D21573EFCBD3A4B2D8196C94EECC453D943C8B27D3E2BF9"
    "B7DEFC2D00EFA3FD131BB48170A263A76366B78BBCC0D807CB0DCA4DAA9948C8240B537E"
    "CC28FEFC3AB60D88A3486A5FC15C4BC6EC099E17D3A6B7B2761EA86980189E0E606BC0B1"
    "E971532E627AC167726902A9D44C50BE24FFC34212B54DC596064E34B9821E6EA5A63892"
    "F187901691F516649E7B01748AF1867A42A63BAB54BF551668D0825E64773752449C64EC"
    "20842E5B8C6760D3379137EB9B5CAAAF469474AA9BB3C1F1A5C257363EB27BE4C7BC5C89"
    "0F5D9532975051F2C4D62D14C0024289F240A6ABDE67C0896DE2EBC84FCFE99CEF7D15F7"
    "9B221617D385782F60564B0B5911EE2D1BE5459058A37C578D0348D1C6E5976DED66B6BD"
    "26D5ED78AFC59561BC28C75FA4B5048AA59D7D7010E22293A14D27B7B6F2ED3B8E5974BE"
    "2E8E46850E30737896FA0A2104EF31ECB24AE8B16FB090AAF578811A60D864711B8BE1CB"
    "538F69A3AF67EF47B81D50F07DDAFB394373F8C8678D938E618184955D14EAB88D715E1C"
    "D22E33AAA7027378C392D76F458463F28A7F365EE708EEFEEFDDB261D0EC1F44EEF0E008"
    "4DDDFCD7DD4F28019D9184091C6E2FF0DCEA261DA0EE746AB6EA802F63C1C374675B52B3"
    "935B937EB7375EA28E3B5198C8FE2C9A677BE319933D981A19505E557A2ED6E007110F0D"
    "95689ED23F62F20525E0029E4789933136B6CD3644F4D63B002A0B5942EAB5FF7B858B40"
    "DC120D78BAE089A65EE5C7128DB3841DF863F476AC15029EC0147A0596D2293D1B5F48B1"
    "3071822E2E8E9F525FFF083732BA87719FE92F6B264D9950458BD2C499E45AF0C6179B0F"
    "116210844306EC289C478FA72F76A6AC46ACC55A32C19B2827127FA1A6D6F36B1EF50CE6"
    "7A458643CAAF9B8A9FE3F28EBB7896520D14827F64CA7D6EFD9B8599EDE0D32F97483875"
    "69ABB52028E042EFC659AEDE4EF4EE4B85FFCD17455A522ADF712C6675F46A3DBF341E6F"
    "C748CC19CE8306C1E3BB762F69B171446D36E63A299D0D68B88ECEE3D7FA919BF402CA3E"
    "BD46FAD001BC250C8177CD43AEEF01D32417303B65728FD25DCEB9F1289815C3132EC1E5"
    "7A376F1C19D6901C398C58A3D7DA3AE23C399EB71FA31A86D1CDA4940B624D28AC93DA1E"
    "9FAC52026C3A110250B5E95F78229059AEB9703377671E47A09496F1DC333BE19C537514"
    "AB5255A27838CB039CB7817D35C387F3A19E21437EE1CDD2C7EF58830284EAF677DCE2D2"
    "1D4B1ED54E2B2B15977A983CF939A9F5AC5598DD73E50A43CDB6BD4CA9F08B78CD9C96CE"
    "D06554DB1CF4A6749FD50B062C702A6A2EE9F6102D7E848254593E430EC9A659E0104602"
    "050B49B70C4F182327F3EBBC4214FA6BD034E2222CA012B3BC288413F6ECE618EAF3ACF1"
    "B0D9AA94A102DA9B56329F4C808AC33D35AF54E6D4C1D12E60734EB0289F1674255AD4FA"
    "CA9644C36388E65C1DA898E4CD6531E89592E1E57BB2988D5788EBE1B013283DDDFA346C"
    "DA5B224F5F8BEFFAC5CA521BC546AA3F1EECB254C597314657DDA91727BA42929B3993C3"
    "C44ED3CE00AA1AF9B00CF9EEFD7530ACF29C50BD0706620372424F58BFB356D28EF5A8D9"
    "0403C52D62DD2F92A19B75E6C46CB4EAC77A9102A6DCBB1DCEA05A28688B94ED3966E956"
    "4519580803795F038255CCF0AB91762898942AFA38E4BF7839B3DEC19D2444D5237212E1"
    "5A491D1F5636D41D0CC3751D96D856F1CD4BF2A3FE1AE8168B2475D11051EB1980C39FE"
    "1";
constexpr absl::string_view kHexPrivateSeed87 =
    "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
constexpr absl::string_view kHexMessage87 =
    "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8";
constexpr absl::string_view kHexSignatureWithTinkPrefix87 =
    "0141424344A8DF889472D431F08DC5A3A28166AA9DD9AC5A9CF18B7D3D91B27B68E26DE5"
    "2C194CE98A34507E30D20E587625BEEF61817B207D678E7D5BF006E681556C2D8F01AF7E"
    "ABD9E86484296D99D471CE69D8DADEEF53B2B84E53B0949D7E0B13E0F7564E6FB2673F33"
    "D3FC8689E7FD3F23C27334A3A6A7DA3E7EAFF481B2C3C48D22AFA40AC10D7DBB45575D30"
    "89DC5B6041D0658F2F6D7083A1F875F07FB5CAC47273B3300371B7FEA083CC1C3123B8AB"
    "5D58907481C53636FFC5F3232FAE529CB42A4CEB8DC59219C9B7854A3AEAC6E0774DAD6B"
    "B16A7F2630F0EB003DF02CA028CFCE3F3DB170F3A23A1103718F559538C4E7E2E1DF0E10"
    "326C164571E27D59162D10ACE2FBF0DF367E50F3A21A5B020A65F4F48A247C218A147DBC"
    "A59E203D462E01F18399A3B53E667461AC1213A6B9424A2B053C3E8243A79B1AFE6D4BD8"
    "2AEBDB15B4FE968A2CD207FFE48E5D256F1B61D75A14EFB6AD8BD299216B988BF964A569"
    "E2A8D07B9FB91E16624673B5EC8D672A430CB683F3E58E1633B377245FBEA9D1F5AFB78E"
    "2A516FEA762D3DA847A61346BEE2E0E6D77FFC0328A01D41C2C395BAAD5953D037DB755D"
    "57F9F82F7C8A0E9A586F0C5ADABF965D9FEA1BAAF14D9179A4D385DD9BA0DB6F32672F2D"
    "D0C9A0A738CCA27CB864B8E9706C599335C3DC168B84277E3AD532C4730C799962093EB3"
    "E2D36A6DED42495CFDF8467C48DB277AD977777D2C0EDD61D76777453A9FE173FF7250E8"
    "FC2200E45D5F276D5B7CCB2385678359B2ED5A1EEB08506B52DE9BD461BA2041D1D556CF"
    "5265DBA97050BB58C34A846F53C6EE20ADFBC723D3AF2D6E84A767060FC309418B3A7DFF"
    "86A2C0041B04FDD12BA3BBA0583A4B7A35334AFD0451D69F34F10AF727184EC0F59D0CC0"
    "88811DFCC180060F2D10CC4467CAF54F4F068A756416E40708274924C42D0003E9701AF0"
    "BF5BEC2ED18B441CB23F8FE76BC0862AC3AD5C7DC06153C2CBBA9A9FA7C50CCB2AC162AB"
    "0780DDD93C4C0FED5CFF981287B0A8FCCC6DF141EDD94969D27EB491F808B30A20CD9B93"
    "4AD69DC7BBB685A7D4C9688D837DE438D7E040ACDD28C7ADF3BD577BFD95BE0F1F2A9BE0"
    "C79D76EB6EBA8F883B779A68312D4E1BB3A79905C49ED0750310324526BC7668461279B7"
    "E8EEF56ADE2F818B84960614B53380079EBD3A9146FF1B57423EE7B946ABB23B6AC2C6AD"
    "B95EDF412D041EFB418737F57CAF04F5A4F90FF810DEDEC8A9083ADB44FE9F7766C18FCA"
    "8144BD5F52551B003563DD0D6B4CE4B730896905F66FA7941F1E88B6EA74BFBB6577DDDF"
    "1796C49B7B8489D4C4AB46BA3B4B85BF9809BD2569281C5F24F7EF9E244F08E3CBDA3061"
    "7DC7A9E8C84C5E5294D5D53356C6FCEEAB677E711B9FFAFC400C3F27548007C4A15BEC89"
    "9D8011930C638C244661B533C1C2A84E1B7C46328500CDEF3A73B045E6510D890DEC59E9"
    "A6A252788AF5A4A9050A5F98C864406E8A0E80AD2E9D91D178782BB71D60596C68A5283E"
    "BFEC1B752944916784EBF60C85661EA4540D558AEEF9DD9D29E92250063CA95FDD962E5A"
    "AAF717187FF20125FBF9EDB8DD000A73F90F04118B2EB01A914F228A1A370DCF174A5F5C"
    "C4BAFC85230CDC02F6BE71BD1FBBB43D6B4A696E8880D5E6431595CEDF320AD30BB01024"
    "1131BEAAB242EADB178D46B277DDC0EF378B72B4F4F19F9CFD7FE7BD49FE6EE6F81FE482"
    "4E1555D9D16352D5E596CF893A84EEFA8DD5D70C196B3223674845B0B7F2A49BD4A79985"
    "253C5EB65447DB0338059B99C0FD643055D9D8F6CA1223DD2726D17F689CC147F8098CDD"
    "FBAB9241AD8EE87F9CDC07707B4ACCA17CE40B6FCEB22DFAA960B41972F43D3FFBB0F08F"
    "BA95C1CBE6726B858F41AE2410FB0B83EFBC9E003C6E031271051257E6A0826ED4DE3C5C"
    "7BB175FDCB2F585513772996F9BE130F6DD636E8E99EF09D8772EA84024CD1274F7567C7"
    "743A067656430A0BB2DCE44C2020D21298DCD04BC48A6FDAF97F0EF988CBFF4E2344CB5F"
    "4194F84F2EA2A0E16959EB6CF8751C2B0D5DB52AA8F41526058118A5EEEC802ECC11B88D"
    "3BC5C92FEB99F754E48ECF49F8FC39036D1B49706B91B663523A5AEDAC44B06301D35949"
    "548D008C0EBA84B711733254EE72A6B40228A9699B6C5E3A63C236B0941CFBC3DDBB39AC"
    "BE3E23523B7E2D9686C46652D7E4D929F5975251DEF9328FC14CA119865ADC0E916DA16C"
    "D0391335AAE5DF649B359AA4591D986AF5010C1AC9667A309F3CC79A19FB6AA020E72DF5"
    "0C1AE2CE60052736A0BDD6356FCB3730E747304A0D0E7A7B59C3256F12576B6BBC446150"
    "5D2B0E09DA0A58D87E8CBCA13D34F424DAE99029A24928B3CE8DD9C794B61FA8D4848FB4"
    "9274022B3B70654B08B1F88B6D7DA5046E667F92E41F8170FB05A2B536A07DA7F41BC4CB"
    "1AC3B0EB4D3AF505E5CC2B4D98E4D9C43021F8FEC85428C2E475E5AE8ECF578BDEB4DD5E"
    "CEB0042874B03C5F7932AA7F2F1447A04D72034575477CF165AC5E93424AE66D0A04262B"
    "308F546C226A2CD7545DB34EB8A98817D4414918FB634FC9D947A637A15C26DCFD5BC60B"
    "4D44F1A0B57759BF882BC33183689B979D64396D96BA3B75A6D6A7DE95784A6DFDEB310F"
    "2F21AC424E76BDCE4810774831E4D2E14A28473D2EB4120830E71A52975BA56C84198CC2"
    "58C7748B936A0277138AB8CA6E62B29E80C30ABC0BC984D3DA6869C035FB258A2513D695"
    "974EE647593D4DBBB8A6ECC05C935FE634BA612B5D7D546CCC446F2F354E4257ED524FB3"
    "5C42EF6221BE1757B3BC077BF64C93F0C443DF81EEA4B323006E557D4240708513086E23"
    "081F0C13DA054B47D62BD82C79BC17F2C488A386CC2456270DFD0FF3D3724A181EB9ECBF"
    "CFCFF63D6AB3D590099E3444E49FF7AF6A79D9C2B112BBCBE08A05DDE98F750BC0AB5972"
    "F523297F5604E35DFD5AD0B57950D4126D2BB10A1840A9C5ED7CA5F9C1A08F29E7771281"
    "2F75138F60DCAD014023B97301B53B04B870080CA3E2CFDC29C88ECABAE877D6B6460BE7"
    "2F04DE84AC78ED50268D977B1B56B4AD7753BFF23CBB6547EF7F997BAA3212158FA5DF1F"
    "C9001D7C7D56CA8A6FF42CBD7FD77CAE658FC5408AD8C255D11295D0E05763F4EFBC1087"
    "35402EE9CCA174804E1DB90EA18C88ADBA36F61647E7871EF1203AB929E91CF257DF81F8"
    "2F4C1954C5D76AFA01A1A68127AEE1989AF4B2F9AFBA67596443F60F2C4249036E96AE6F"
    "E2B383E90BC360F8F7C1461A9F24FB0DC8CE57D2E7BB543E3F78C047E0F12D781086A782"
    "DD2D9B133597FBBF9AC5A444AB3C3523E176E97D5F6D82183B4252FA35DB1D6C1A7DC566"
    "B1007F8E889AADBA9E51D0FA662F10AD61B713378D2F22C2E7AB01B9B04C2DFA6748E523"
    "F01B7EF497439E24D9D0071FAC7676FDE2B56DCE2394E2CBC9CFF55DA7D23FFE0D6581D3"
    "E97BB2487ADD9B957F1DB9D399BF84E1564A0C92EBAAC332CE2EBC291E8B5FD0F3734347"
    "B1D8B8C940D3B438A265CDF36AD96DBF6254229B96FDD2CD585C1A7686055F8337395A92"
    "98D94FC8348F73E41DC9870F1C8F325113579CE0FBB729EA270874395B81F23205D26D2D"
    "A922E997C509AC213411B667D06DC4EE0A699B8D1722AF1903C6927EEBAAC3AE2CCF70A4"
    "47C8BB7F48B3C7198EE933D01D560AAF42EC7468EA81AB8559BB013844103CBA500D1540"
    "393BFB911A5BD902D06B3B4BC0F7DC675BC281E5E1E2AC0BC4B762AD18D4631BB3ACA3DB"
    "02CCC5D56432315D0E3FD1C4C8EEF48F9B534C1B7FE0E38000C1AA0D3D49A68BE281BFF3"
    "C1DC4923EE62B44403221DB2D456B2D078394483159197F43AD832C75606E0576FE0268A"
    "0FEEE7646A6FC156D34DE3C8B13A72EF26E33E7B6A41B567AB1CABC3062A8EA10AABE1FF"
    "EBA682E1B4AEBA5DCCBDDEFF105F11A35AE84B47B748923DC7538576712F1545A702AD7A"
    "7B6EF7DA967C43278CF4D53E09D377F3CD93624B33ADD34F51292E98DA4A8729557F7A31"
    "129057EEF37B89A88B08285D749E209D1EBE4BF97E06F8A46EEBFC3A31C9FB0B0054B1BF"
    "AA47281FBF312B59E8A4D8157595F8EFA1E80350EB9AC16E1F300872B39F5FA42C742DD6"
    "95717078C3886F5CC2A93236FF51DADC1DEBE783FF7C287B7F4D3E9ED7115DC7CD44488C"
    "29E982D65D1CE41BA065AA948C52B4CBEC24CC3E3D6E8139ECA8003F609F0598DAA983E5"
    "360187640BA411D9D5ED3AB8C790AE74887512CA90B0A96FD0CF45B4CA2F6DE0E382C225"
    "99CD2FFDEE6FD5AECA0A2F29AAF069C61272F70DF4A0D34AD3D2B3475CAC8A832713465D"
    "C9DE904F26D0217115FB081BA0BC2A10C2455FD977674145A33BDFEDDB4E4FB715236818"
    "F02A7C13C1197B97C86F103186BF5159701A5158A4E49DD24188D3BAB5137BE43FF6C594"
    "B976C7A7F8C3C92A6410B0A6E748BD172B5C8EF327BC9A8BE9E379CFE12A64E40C97069C"
    "ABECC57ABCDB0C96FCEE703566141138B35CD2295607384402EA4C1B9A6591DD6D3C3031"
    "97BAF0B78F2DA9FF52B64D0C0263E9D4EB5FD09AD3E35A775B14C54D4D6433F1DBAC9C17"
    "2E330508400710B783CBF8E96BD0B8262415527C37F408CA3B761237A08602225E8EF286"
    "E35B6B08C71240B50D2185BCBB47D75E3E73B2AA68218D53BA811AD506BC99D71D3B6B2D"
    "35A0A9E34B7ACBA12948C08790107505B054B4A828C26974056EDE75C1BAAED177A29ADA"
    "44600B6BDABBA2BB0E23E3B3CCFF462143A90144D4BBE6968293EE04171798FCCF47CA45"
    "B5695C26DF18FB2745817BC249757E3613E8D771153D65DE7B4B4B1594A0A9D30C907ABB"
    "F7DDAAB3B421A0E805702B89C4C60A0E4ADDC01C5A51843DB066EC5F53D4BB2D70359B23"
    "74E9D23DE6A374BC8D4E01F4DB24A1D455E8FEC641B8C7F7E82B22C0F3C195C9E87C6BF2"
    "4DCE92F3DEF54AE5B549CE8F095C09ACB01B0F6619CC4311444E3E4A07B9D8DD6DC9ACA1"
    "5E3DF12CCBD315855240BCE7AA6C1BE58069FECA1A789C327ECBA288AA5C52202F663305"
    "A405E759AB0E8DECE984EBECD93D0BD64947339C139787362B7C1EE02640FFBD81A9EB6C"
    "90E1400A7033C35CAB822CBACBF6F3397C1195B1C6B05E9447F638E97143E0DBF1492349"
    "7154E20028C282A09F006DB42C61E8AB94875C22940E9ED850FA633F640F57637871F1A8"
    "90BA3E5635828ECF5F2BFD3F540062CF45E8727D053F56D704B73F37E1B99D4EEC508285"
    "0838AF09FE53DEC2C9E5607B095C49254E0EE2EEF40B05C677F5F9A70A424D1D67F1CAD1"
    "6293F6485F149D2BE1A699A37434246E2D9E4F3A9BEEAD5E73AEED5A5A01E4A931CB60E5"
    "D3DE433A17E12615EFA06D6B7ECF8487025574A09E077AA20832E2EA292C0249FBF5C3F7"
    "9C4E01E90FD18741786A33314835EAAD8C46DD2DD1380DB32ABF3DBB5B0F0883A34AA8B2"
    "3B4404432B6D2893BE1C47A71454F9E429F918FC87CC1A0D02CB29F604937AFBDCDEE937"
    "AA67501E9BF113AB08518501865D6C53BE1E4759A9784C55147B5A83AA764B67913D52CE"
    "C438E0F3AF142F82A3FD6B9247611070416FE14F51D65E54D34AAD84796497B057B7A45F"
    "C59EEF8D74BA4EE47E4E6AE426AE060D251928D9E98132944ABE1FAE99AC1218A643A982"
    "773ED242B342892F1660024BD5848B52425932A67395732DB81A1DE2750869555374D493"
    "0CAC5ED2EBFDE371BB562F1D29E69B928BCDDCA10B307099212261142823357BBCCB0E26"
    "C6503DA192135EE95FFFD4EABBECE9E9DEEA4E3165F178B3BB65486EC2D31EC54B93C0FC"
    "5831743BD11E8464DBE413A09CF83A805CD3DE2E2198C66F27A9ED21974FDBAEA8D12EFF"
    "499CA8ABC2B437BDF6BD7A11C33F07143A52D21B72C9AF1C001FE8857CDAE2E3D90E070F"
    "4CEF17058E3171F21983D91B77D3A86C93289B4D4362D67C2B6942913BEF11BDEC221933"
    "31AE578B4C6826552A393CD07D69A1F0075D7D2C2683D8048582C46A3D2F52F1B8916534"
    "E2F565CD0C848AA469617D08ED4B31C6310D37AE89F9B69A56603B9C0B6E2AB97D0F9EF5"
    "989875D5ABE0B3048AF3A78265827C5DE2933072283B1BBBFFA7BBDB04371F5B88634ED9"
    "184D3D68EB1E5124D4D7E0517A4F92CF638DEAF4910BBFAF5F58DB78A5AA5F6C0D1DD48F"
    "AD3E2B9D8C2491F304468F8249ED5AB8F46899F6E9D976FA35FDDA90FE5399E130313CDA"
    "A4577FB00E9ABA9570C894D77725ED11DFABB1DBB930008FF9A1042D3CA268F8B00F5F4C"
    "2DC0DF84ED00EEBA642D1606F3826CB99AC5F7EB197C9244A7937799D66DFB211103FBE7"
    "69546EF8675FDE9D8D01BD790C3BF43775F950CE131966F6819881F976D764DB5EC3902F"
    "D645F8234FD4423043C2D2FBFB1478FE4D8C2877866F6D7FD88F4EEE5A9BB9783B25C0B4"
    "0C91532ABC1207B251AD86751A2D3298A3EB1A9FAAFA182445519DAAACBF19666AA6BDC0"
    "E2F808BCD0E3F4FC495E8CACCFD2DFEBF1F7F908445D96B1B4C5C91D637175BC00000000"
    "00000000000000000000000000000000050911191F2A3237";

TEST(MlDsaVerifyBoringSslTest, TestVectorSignVerify87) {
  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = HexDecodeOrDie(kHexPublicKey87);
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *key_parameters, public_key_bytes, /*id_requirement=*/0x41424344,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_seed_bytes = HexDecodeOrDie(kHexPrivateSeed87);
  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignBoringSsl(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message_bytes = HexDecodeOrDie(kHexMessage87);
  absl::StatusOr<std::string> signature = (*signer)->Sign(message_bytes);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message_bytes), IsOk());

  std::string signature_bytes = HexDecodeOrDie(kHexSignatureWithTinkPrefix87);
  EXPECT_THAT((*verifier)->Verify(signature_bytes, message_bytes), IsOk());
}

// Generated using BoringSSL using the previously defined ML-DSA-87 test vector.
// context: "some context"
constexpr absl::string_view kHexSignatureWithContextWithTinkPrefix87 =
    "01414243447fa29356bf7b9a8dafc2c3125dc545a2a5913426b51502b7162cbb090de5189f"
    "995a7b5b7a279a4ecd1761b39c87ff9cf30e551cc88bfa993de48eb21297ebce9f76a82321"
    "b4728f7180e1ae49165e1930dc9cb38b01b99ae9db1e58225eaa5733304c7b3bcc8df4a1bc"
    "823bb678917da1485ab19dfb669c28367641cbc6ddaa12a02e8c7d8261eb2338d9d0e9b9b0"
    "34153db2b0a2d8dc66ed703a9e101a26b82c81f02b717b0e268c4425ad76dbec96031032e9"
    "f7e79f4d8cf5035830adce9a6068a5e65d57754de1f4e400b1b0591e1b0a617a0495e7f751"
    "2a8d5fb5a2fdbd51e97af3749889db684fea8940f2095d9f2c01bd53cea6946ab2b56e44ae"
    "c2434690239abbb21a30772aee79fcf18db868c9621052d23e5fc2fff1ac125c3f531915b2"
    "566736732b8500d6061d00579179be539ea2edd2f9f9d6c20869bd8a2d4bb6bcca91ac1a36"
    "a38aa26e90173e958e5ecbfc00a66d69a124df8f08e0e7addc1dcce845f8b8cc127c484fbb"
    "bf36bf344e207b35fe209a6014a94a5d555199aa8fcfd49c5cb0c9296b7ac48160b58be682"
    "bba8618f4c1e097bb29296feba5b5e369ad872a2e905b424358a4adeb7414c156191e1d52c"
    "3fffd8461de97c1a216c021db5ef633ea3b95a86cdad7f1aa1bdbfda58f2c6ee5d49ea119c"
    "13a75c0bf09cd2722b7b17fa1c09156a9ecaf249c4fcb98f6115e10020c4105d2ee3adcb86"
    "8333b37a4207e8f0c20ffd73ee89fae91c4939df82e98c26a149e95bced0aca72cc078cbf2"
    "80826e2e290b57cf34d78c9b83a685589cb69c8d742e3847bb7f413c20abe80d5030408d9d"
    "6a2a31b1ce223064313daaeae6144b950cc8627a7a0a46fe001bb9a911a3a3c45ad852e6b9"
    "0df6e813bedb47fc578cd8e99ec04c79758ac1284a780b66cc77f770978a81d77bd2bb074c"
    "fdf8edbe3025ab9bf6b3b4316b826554842950f581df75a8c73a65517b9bb8a5bce6c65b83"
    "400bde724c9c5b926c8ffe4024b34ee5aa2be757ec93ad9a3b64af09e2135981c9c7376500"
    "4b6fbacf010ff35ed8accf5e560a68585a60c9b7beaf84634506b8c307eed3b9a0bc5cd5f7"
    "a07479cbcb94eb5c54fb2b6cae838b95359a08b6ba59febb806a070191893397307d727b2b"
    "5dd0fa213ab096a0ad773b771e4238fc5e67b46a5ff4994a809bd192d4c1cdace1c95c834c"
    "8ab33b5d23f2131c10ccb16ef41576b77e87b30c95439408e7cf3544c2235bbef85e600ad1"
    "48198f031ff3b356de33227f0e0d56bf7ac91ec82ad5e1b1e4eef084bc62de1c13ec09b123"
    "6283815fe11130aec0b03a31484f4c6eba55ca9da4925ede29afec28d894c485ecb396156e"
    "22e7bc7ad99851d140aa8d84f4f836528f1625a4fad53ee538169849563465700f32f56050"
    "9a400e690903f4116b0c77bff53f8841d982d36c9045322255a65b6f7b03267f55977d5665"
    "9d071197151d471a19baf675ef1e04f752bf56aceac30031899815b5ca1161f4aa6bb8e174"
    "c9b6ae7feb3d36af57d941890f35a1df02afb05036208e5b781927b96014ea4719df72fab2"
    "7cc2973010ae9e51d1ec5faf58698ba0bc7db3c50a321858e3b1b7c15f0b5a8bfd11d45146"
    "a530ccf9a56183a94076068d56d35cc268d08f0d773b8d9bf88be72dab10902d28c11e5930"
    "6c9f9db003695dff8d1248b6a7d556782b4b3a136f3852e03b48984bfb3f7bc1d9f6c53a70"
    "8c78289185f8ab0ae2351a5e4cf8782fd114e82edd521ae7820a0b430470b6770c7a33bd21"
    "bbe72a857e44128cdce0a7fe092f180493d7248c9b96956bdf20996172312a4cf12b5f238b"
    "e01efe0812f59228ab5db58411aab6751a3d619db3f0450858cc67b6662b3373a8451b3451"
    "b569c32464a96192fecf9fd89f0b4527e822ddbf795cc3b15fd45360bda4310bad4c213201"
    "d2b0cd50d3211d9b0b26a373c2812d6757c37f4e0d1239c8f30a538f5623b7c020b1c21033"
    "eaf976c4e055c6aa35d58489ca019b291fa2c81a5e6060861040668455ced77f963da0de8b"
    "640506325e9a5ea0d7c5c095697d0ab504e9a69fb0687afc0ada24ba42d519134615b54a55"
    "c641419553cddcd2e1505248f196beeb0ceb2f767afe5cae0bbb0f033777f49c5f175eabf3"
    "a4fe54bf44d02b73ca6ae5b0fe984f358ecbcb30b99b3a375f8d2b0f24d06b03c369e28513"
    "fe445d38addf2a3977f09295f8a24615ded22a46834325fc9443f4f783294aa872128a05cc"
    "ced774ff665508dfedce27716e5a27c604357c9bc61f9ee887160ed67e2cff3b917c43a570"
    "c805e99f91388e8932ab7d82bc6d1156aa5cc3af0250dd6e3b8387aed6a1783c2778eb3c2b"
    "482009bd42f63eb20db1327dbe7233b4fc539ea45221674117ae825df50a8fb150e2db3207"
    "f0c1ca423f7329a30b452347626d70113a4bb514c80354f011b361e36025ada8d0bf554325"
    "088228b20442a43f7f3d77afccd9e8c9f5dac961e7557c5828db5458783eb587d4cd85224a"
    "37c47bf8379089e6f7fdcc7c2846768450b0c4e02c31f8500914db5309fc35e5fc34736a70"
    "94f42cc6e6064fff967a2fc84d6f08878591179c0f4b6e10fc0ce20537b2227aaaba2a1200"
    "9192958f0bcf2e561ff22cd1d510b7fe740b931a354179fcfe3e939c69a229c8fcf556b151"
    "9afebf4608e36db0c1c57604fbfa8fb7e87281a7ce6d6658fcaa5670f8ea3148bbbf99fd6a"
    "fabf2c84208925b810befdcf7a78ba32975b1ac8451bf499fcfe64db13055a238419184a8d"
    "e8f2d533c59dd624513e693ba1853a8fadd8503b4a1940186d2d3ba656707558e4b2b9caec"
    "838a7745cc053bab6e66c3d887478965fcc3c739dff15e801f529c98f02c4851127f4de917"
    "8abe4d59ccc1523c809107b6ddce3abf5bff2874d07b74294bac3479feb67df97e66696410"
    "59e1b5058e10eabbeb4a13197785e3931f00657a2452e326c904bda91cf548a34a9c8df031"
    "520b245802a142ab2af198b9d5948fda25631fd9d0d497ac4ee02c706530cde5d418caff15"
    "773c4c2086dee455af08f1271321e640639cc710cf4f9dc8079ee988b49d4bbe31054f91a1"
    "199d8f29a441385eff8db3ccaa4f2d3268996f5a744d7b38374185d853097e1eec860a128f"
    "00e0ae234a13523c3fe9903e5a89182d6b943fa2c439cc171617a54a86abbe72a4d363ecdc"
    "3322821192cc274db716706c49c0cb2479a467728a5a33f9996a39678f19ffaf193d80b427"
    "e8de3dcbede2f79979daa55d9ecb85f209c2e7d138ab24824296a74b4a6ac54308d2147289"
    "6359012948a82e8b5502ebd4e2a07eb7d1c001e2737372902cc6c44ddf2bea3a4c2c49bdfd"
    "7070eb48054e10a4e5dd4902de6fd6509dc077aa94b63a2b3e6c2b1aeeef5c19cf4e5f3358"
    "752d9bf5e99de2f60b7611779ff0f642ad63c6371b9aeecaeb62a4099fb92a864eead95493"
    "b5ef8d8372b3eb78f1e8702cf6f3f2476757c0d664a7501498806d4330129c39f32cce4cd2"
    "3a081f354c546857b5f1bad4d7d7eb0d95d0d6b75181c0785a66f83c60f6e075e06c95839a"
    "6b43ec23e8a0824afe35daabcd4a240d35bc4d80de2303a3968dee1b655e2d38dbb808119a"
    "01adef63992284547e61fdf53019b570df868e3e6173c95b7a9617bd61a784d1f5c5335822"
    "54f1c2821a5e93323fd3781fe69d627dcb46ee5d699d158404e0ca8132da1ee7aeec05e3be"
    "1c10d1070c17bf4be3e91c472bbe0d19d234c9e8ca9dfbca40ae73648b74625fcffbc4b24e"
    "8ac91598f09324aace025eee4affbcc56b1b4e958bc45c0f20c3ecfb900b201f34a13e54ff"
    "5abe87a790a76bab6af7e874b3db55bc69d65db8e6d1827d3cec5568dc602b9e179ea0700b"
    "fccff9ee9d3a3cdb11f5902e23030d2514482f89731537b57abfc8cd203243f6fdac172cc5"
    "fdb844a731ef8631fc112419e0ea67177f5d90ed40a35eabb280512fad4535a5d72ac79ad7"
    "bdbae90344450c6762362edeae04c4142209b558dbe416c5e1e11792f09ec0ee78cc91252f"
    "3cbcf1e1fc9626bf0ce529ec28190332c03c0f74f2078a14311328fb4a36cc42f3b2703c8c"
    "e166b7e8e7bb56eb27aa8abf1ddcecaba1cdb75411bdfca6d504dbe18c06e374c9f3ac12dc"
    "82d57565e4eea6f70789031168d7817b082688d9b1b73fbe2a4c8be997139743be71753c60"
    "ece92f47a204fd363f99196e19e3e099d7e36be148e848d40002f1d874365e9b5d0d8aeaf6"
    "28986afbe6f32313dba073f6100ad0928a762b3fa00866316ca5a3e8e22603226cb831fb80"
    "1fb00ce9a9f962232092a533c396c2c3c2a8fc651044d4a8a3830b2193714ecf85bd5c0c10"
    "8208c17cd69dc38adfa81c901a5d0fecb668008f014ec79411fd7cee0b044a27eb7534ad80"
    "4abef5d17b7d9ed0b65357f890f446649a5e4583e0b2955857b8aa25484414c38b34db09ed"
    "d4c80c89244386f9b88796f5b14aa7d4c823e54b711d40024dcb92d88ff6130237db4e7459"
    "fdfe55f8c9a3ee036a1d72629a01c6ce6e563c2045774ab7eb41a574a0214a2b33bab40e07"
    "7822508f3b59d3a08a4fe40dd7665ab8297b78e1f92c04129212b909e4621be7a0869cecaa"
    "d94f0f46f61f22eb061837470bc914fe7e8868fe6de04435730652a9ddb7de5a7d1fccbee8"
    "f65ea9ad1ae1d0df9aced09b4587f028fda3b0ecd36e2a41ee90fe9eb36bc07b3363085ae2"
    "5ef59f409854529b784989d695e4ce9a73bc4c200146089ed27b4f68f8441050af0dce51c4"
    "aece7507189b594ff7f1b1fb1159caacec25a6e16b4e08e3129973de283ce7d4d1b8ecabd9"
    "d23ae344fbe93bbc2c56ff6039ecdb21aa7c78d74c346e66843492d568f4c73f872ab2ac4d"
    "8a09a28c7dcf44a09728b347549e7ea5bd904e5e78c0e766bb883add5de2da7a7c93b4ef1a"
    "7592efb9d19b85a672a028be18c3c998c525ab6dda573937c3fab28adf4b293d9c7e86188d"
    "5f3d982830b90e1f9cbe167ea15c31120750ebeb406cb97b7e292a1d926b6f77e32c148b35"
    "7541d774aaddebc693518586a833484c34a0aef4f588e17a83678ea71210a0a449430b14ba"
    "f973e904e2aa6c9ddb381dfc21f88a2c5a3afa566318e2a99bad64ca0cd0ef04f33177c8d2"
    "9badc7c9cfc5b714a526b26757766bef85f3d1f61a66bc3482527ec5584d70c24b15feffdd"
    "d1440dfc9b678c0e88351956d609c9b199e3094d772c35c446556bb29466b15d895da46b73"
    "9b7ea8f57ce968d4f3f8d7a966d6854586d4b544f1d60a6400a1c61eb932b5dc5196571380"
    "56a81cb1ad402b4f746bc91badaede81fcc9955f611aa9a848a3220a253a5516ebe58af7a8"
    "3c2833ad4994ceff112fdec66ac41442aa3c65de406abc42bbdf328f364478704e6506bb9b"
    "f55bee656e13dedcb42a90cd53a51f15cf8b765fe708723550933ac25ec2cd271cdb419913"
    "da0dc3eced387611203462cfa1ff0641a29ca275dcc025583ebe752c4be5f18a193902c5c2"
    "72265d03900a3cd883138f72a2de15b895ebdd2f56cf2865d06400af1e4bcad71b64f35526"
    "5e61a6a112684552ef3ba6a3a0a59501e201cba411e61d405010fa42939244ddf5890f2942"
    "9e6daa19e6ae3aa46d43764941f28b3c102a82dee3f141b5bd28ab19991dd1a6cc0a661087"
    "a4a3388d73dc60837b525c24a7fde3d977c1af38cbeff308e101bb7602d8d1f87bfd46488c"
    "ef5d6819c4fd8f14e89598b7b42745e6fda33204b2ca631d82b17dfc2de7cc628e073f3d27"
    "ec3a6694151c5bf323f72bc10f10d2e581948b8bb12bdacdce77404a84549b1cd4a6485092"
    "4ee605a84c7cf5fb78b45e78e1f9c38189bdfce7dc229b23c6e543b1eff9816cbd180db597"
    "eafb7af0d211f7920656477df91c7ca9beeb838bb393e79f457bea35cc35f98caa167af83a"
    "b669d078685f8318f57c066b7a8b7eb714613d3b70e9bd0a93ea4b6a4920e07b626b692a38"
    "590f0244007c38b82b2cea893875763945611e8a1daea4efcd0280f3ff4f7008c4754dcc85"
    "7bc8d487b2dec1ae16ec800f48b00d641777e1be64b987fa27c64fa5d121d0a8b3608ff7ea"
    "938ecc67cff678c0ecc5c5fc3cde650b2ec2223bc768b5498544eafacaac64cbe9563318bf"
    "13bfac7490f7935ffe4122ee462136149e60804608a540b2dca398cd82e9a1f499b9f5dcf3"
    "2761227accc9a350c8834a366de6572b0bdaf13015f1ce730b619fba14dcf0f9cc56d9a0dc"
    "901d82ca54888eff0480043bc7d39e854c12dd3daaa030ee35c5207de81ac9d1bbe5c479af"
    "7ff3bf30b31a7997cabd9ed3c25bd0169d51cca7067aca733367a4075dd07fea728f7f2451"
    "669583349333e09237eb4c35ce3ab66ea3a1099cc148f223f657e246d1230ebd87bd14d004"
    "9f43fe9280b6102a6a5adbd11638f6d6ed08e60e861f784dd637fa82d60a62a6d3c48d0b18"
    "47b6c6abc0cbcce1e3758de8f3fa0b163f52648fb2c4f128555e89a9cbfb015a96c4d32f46"
    "a7cc0e25545b00000000000000000000000000000000000000000000000000000000000005"
    "0b10192025292d";

TEST(MlDsaVerifyBoringSslTest, TestVectorSignVerifyWithContext87) {
  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  std::string public_key_bytes = HexDecodeOrDie(kHexPublicKey87);
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      *key_parameters, public_key_bytes, /*id_requirement=*/0x41424344,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string private_seed_bytes = HexDecodeOrDie(kHexPrivateSeed87);
  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewMlDsaSignWithContextBoringSsl(*private_key, "some context");
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyWithContextBoringSsl(private_key->GetPublicKey(),
                                         "some context");
  ASSERT_THAT(verifier, IsOk());

  std::string message_bytes = HexDecodeOrDie(kHexMessage87);
  absl::StatusOr<std::string> signature = (*signer)->Sign(message_bytes);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, message_bytes), IsOk());

  std::string signature_bytes =
      HexDecodeOrDie(kHexSignatureWithContextWithTinkPrefix87);
  EXPECT_THAT((*verifier)->Verify(signature_bytes, message_bytes), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
