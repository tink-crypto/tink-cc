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

#include "tink/signature/subtle/create_rsa_ssa_pss_signer.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/big_integer.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/subtle/create_rsa_ssa_pss_key.h"
#include "tink/signature/subtle/create_rsa_ssa_pss_verifier.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::StartsWith;

TEST(CreateRsaSsaPssPublicKeySignTest, SignAndVerifyRoundTripWithGeneratedKey) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  absl::StatusOr<RsaSsaPssParameters> params =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(std::string("\x01\x00\x01", 3)))
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      CreateRsaSsaPssPrivateKey(*params, /*id_requirement=*/0x12345678);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateRsaSsaPssPublicKeySign(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::string> signature = (*signer)->Sign("message");
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, StartsWith(private_key->GetOutputPrefix()));

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "message"), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong message"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

using CreateRsaSsaPssPublicKeySignTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(CreateRsaSsaPssPublicKeySignTestVectorTest, FreshSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeySign(*typed_key), Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeySign(*typed_key), Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateRsaSsaPssPublicKeySign(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, StartsWith(typed_key->GetOutputPrefix()));

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, param.message), IsOk());
  if (typed_key->GetParameters().GetSaltLengthInBytes() == 0) {
    EXPECT_THAT(*signature, Eq(param.signature));
  }
}

TEST_P(CreateRsaSsaPssPublicKeySignTestVectorTest,
       FreshSignatureDoesNotVerifyWithDifferentMessage) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeySign(*typed_key), Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeySign(*typed_key), Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateRsaSsaPssPublicKeySign(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, absl::StrCat(param.message, "a")),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(
    CreateRsaSsaPssPublicKeySignTestVectorTest,
    CreateRsaSsaPssPublicKeySignTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPssTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
