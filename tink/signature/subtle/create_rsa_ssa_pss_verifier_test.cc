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

#include "tink/signature/subtle/create_rsa_ssa_pss_verifier.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/big_integer.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/subtle/create_rsa_ssa_pss_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Not;
using ::testing::NotNull;

TEST(CreateRsaSsaPssPublicKeyVerifyTest, CreateVerifierWithGeneratedKey) {
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
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      CreateRsaSsaPssPrivateKey(*params, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify("invalid signature", "message"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

using CreateRsaSsaPssPublicKeyVerifyTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(CreateRsaSsaPssPublicKeyVerifyTestVectorTest,
       VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(CreateRsaSsaPssPublicKeyVerifyTestVectorTest,
       DifferentMessageDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(CreateRsaSsaPssPublicKeyVerifyTestVectorTest,
       ModifiedSignatureDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateRsaSsaPssPublicKeyVerify(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // The first byte belongs to the output prefix, if the key has one.
  std::string modified_first = param.signature;
  modified_first[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(modified_first, param.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  std::string modified_last = param.signature;
  modified_last.back() ^= 1;
  EXPECT_THAT((*verifier)->Verify(modified_last, param.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Shorter than any output prefix.
  EXPECT_THAT((*verifier)->Verify(param.signature.substr(0, 4), param.message),
              StatusIs(absl::StatusCode::kInvalidArgument));

  // Missing output prefix when the key requires one.
  if (!typed_key->GetOutputPrefix().empty()) {
    EXPECT_THAT((*verifier)->Verify(
                    param.signature.substr(typed_key->GetOutputPrefix().size()),
                    param.message),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

INSTANTIATE_TEST_SUITE_P(
    CreateRsaSsaPssPublicKeyVerifyTestVectorTest,
    CreateRsaSsaPssPublicKeyVerifyTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPssTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
