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

#include "tink/signature/internal/rsa_ssa_pkcs1_verify_boringssl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::NotNull;

TEST(RsaSsaPkcs1VerifyBoringSslTest, NewErrors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const SignatureVerifyOnlyTestVector test_vector =
      CreateRsaSsaPkcs1VerifyOnlyTestVectors()[0];
  const RsaSsaPkcs1PublicKey* public_key =
      dynamic_cast<const RsaSsaPkcs1PublicKey*>(
          test_vector.signature_public_key.get());
  ASSERT_THAT(public_key, NotNull());
  RsaPublicKey valid_pub_key{
      std::string(public_key->GetModulus(GetPartialKeyAccess()).GetValue()),
      std::string(public_key->GetParameters().GetPublicExponent().GetValue())};
  RsaSsaPkcs1Params valid_params{subtle::HashType::SHA256};

  // Small modulus (< 2048-bit).
  RsaPublicKey small_pub_key{std::string("\x23"), std::string("\x3")};
  EXPECT_THAT(
      NewRsaSsaPkcs1VerifyBoringSsl(small_pub_key, valid_params),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("only modulus size >= 2048-bit is supported")));

  // Unsafe hash type (SHA1).
  RsaSsaPkcs1Params sha1_params{subtle::HashType::SHA1};
  EXPECT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(valid_pub_key, sha1_params),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SHA1 is not safe for digital signature")));
}

using RsaSsaPkcs1VerifyBoringSslTestVectorTest =
    testing::TestWithParam<SignatureVerifyOnlyTestVector>;

TEST_P(RsaSsaPkcs1VerifyBoringSslTestVectorTest, VerifySignatureInTestVector) {
  const SignatureVerifyOnlyTestVector& param = GetParam();
  const RsaSsaPkcs1PublicKey* public_key =
      dynamic_cast<const RsaSsaPkcs1PublicKey*>(
          param.signature_public_key.get());
  ASSERT_THAT(public_key, NotNull());
  if (IsFipsModeEnabled() &&
      public_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      public_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      public_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPkcs1VerifyBoringSsl(*public_key);
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(RsaSsaPkcs1VerifyBoringSslTestVectorTest,
       DifferentMessageDoesNotVerify) {
  const SignatureVerifyOnlyTestVector& param = GetParam();
  const RsaSsaPkcs1PublicKey* public_key =
      dynamic_cast<const RsaSsaPkcs1PublicKey*>(
          param.signature_public_key.get());
  ASSERT_THAT(public_key, NotNull());
  if (IsFipsModeEnabled() &&
      public_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      public_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      public_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPkcs1VerifyBoringSsl(*public_key);
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      Not(IsOk()));
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::string_view(nullptr, 0)),
      Not(IsOk()));
}

TEST_P(RsaSsaPkcs1VerifyBoringSslTestVectorTest,
       ModifiedSignatureDoesNotVerify) {
  const SignatureVerifyOnlyTestVector& param = GetParam();
  const RsaSsaPkcs1PublicKey* public_key =
      dynamic_cast<const RsaSsaPkcs1PublicKey*>(
          param.signature_public_key.get());
  ASSERT_THAT(public_key, NotNull());
  if (IsFipsModeEnabled() &&
      public_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      public_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      public_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  if (IsFipsModeEnabled() && !IsFipsEnabledInSsl()) {
    ASSERT_THAT(NewRsaSsaPkcs1VerifyBoringSsl(*public_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewRsaSsaPkcs1VerifyBoringSsl(*public_key);
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
  if (!public_key->GetOutputPrefix().empty()) {
    EXPECT_THAT(
        (*verifier)->Verify(
            param.signature.substr(public_key->GetOutputPrefix().size()),
            param.message),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1VerifyBoringSslTestVectorTest,
    RsaSsaPkcs1VerifyBoringSslTestVectorTest,
    testing::ValuesIn(CreateRsaSsaPkcs1VerifyOnlyTestVectors()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
