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

#include "tink/signature/internal/slh_dsa_verify_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/slhdsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/key_creators.h"
#include "tink/signature/internal/slh_dsa_sign_boringssl.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::testing::HasSubstr;

TEST(SlhDsaVerifyBoringSslTest, BasicSignVerifyRawWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST(SlhDsaVerifyBoringSslTest, BasicSignVerifyTinkWorks) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters,
                      /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  //  Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify signature.
  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST(SlhDsaVerifyBoringSslTest, VerifyWithWrongSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());
  std::string message = "message to be signed";

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Verify with different signature.
  EXPECT_THAT((*verifier)->Verify("wrong_signature", message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid signature length")));
}

TEST(SlhDsaVerifyBoringSslTest, VerifyWitModifiedSignatureFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the output prefix.
  (*signature)[10] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST(SlhDsaVerifyBoringSslTest, VerifyWitModifiedOutputPrefixFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters,
                      /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Invalidate one byte of the output prefix.
  (*signature)[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(*signature, message),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("invalid output prefix")));
}

TEST(SlhDsaVerifyBoringSslTest, VerifyWithWrongMessageFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      NewSlhDsaSignBoringSsl(*private_key.value());
  ASSERT_THAT(signer, IsOk());

  // Sign a message.
  std::string message = "message to be signed";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  // Create a new verifier.
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Signature is not valid")));
}

TEST(SlhDsaVerifyBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<SlhDsaPrivateKey>> private_key =
      CreateSlhDsaKey(*parameters, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Create a new signer.
  EXPECT_THAT(
      NewSlhDsaVerifyBoringSsl(private_key.value()->GetPublicKey()).status(),
      StatusIs(absl::StatusCode::kInternal));
}

// TODO(b/372241762): Add tests with actual test vectors once those will be
// provided by NIST or any other reliable source.

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
