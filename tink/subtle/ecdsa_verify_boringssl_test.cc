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

#include "tink/subtle/ecdsa_verify_boringssl.h"

#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::
    GetEllipticCurveTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::GetHashTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::GetIntegerFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::testing::Not;
using ::testing::NotNull;

class EcdsaVerifyBoringSslTest : public ::testing::Test {};

TEST_F(EcdsaVerifyBoringSslTest, BasicSigning) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    const internal::EcKey& ec_key =
        internal::GetEcKey(EllipticCurveType::NIST_P256);

    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_THAT(signer_result, IsOk());
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_THAT(verifier_result, IsOk());
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    auto sign_result = signer->Sign(message);
    ASSERT_THAT(sign_result, IsOk());
    std::string signature = sign_result.value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_THAT(status, IsOk());

    status = verifier->Verify(signature + "some trailing data", message);
    EXPECT_THAT(status, Not(IsOk()));

    status = verifier->Verify("some bad signature", message);
    EXPECT_THAT(status, Not(IsOk()));

    status = verifier->Verify(signature, "some bad message");
    EXPECT_THAT(status, Not(IsOk()));
  }
}

TEST_F(EcdsaVerifyBoringSslTest, EncodingsMismatch) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  subtle::EcdsaSignatureEncoding encodings[2] = {
      EcdsaSignatureEncoding::DER, EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    const internal::EcKey& ec_key =
        internal::GetEcKey(EllipticCurveType::NIST_P256);

    auto signer_result =
        EcdsaSignBoringSsl::New(ec_key, HashType::SHA256, encoding);
    ASSERT_THAT(signer_result, IsOk());
    auto signer = std::move(signer_result.value());

    auto verifier_result =
        EcdsaVerifyBoringSsl::New(ec_key, HashType::SHA256,
                                  encoding == EcdsaSignatureEncoding::DER
                                      ? EcdsaSignatureEncoding::IEEE_P1363
                                      : EcdsaSignatureEncoding::DER);
    ASSERT_THAT(verifier_result, IsOk());
    auto verifier = std::move(verifier_result.value());

    std::string message = "some data to be signed";
    auto sign_result = signer->Sign(message);
    ASSERT_THAT(sign_result, IsOk());
    std::string signature = sign_result.value();
    EXPECT_NE(signature, message);
    auto status = verifier->Verify(signature, message);
    EXPECT_THAT(status, Not(IsOk()));
  }
}

TEST_F(EcdsaVerifyBoringSslTest, NewErrors) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  const internal::EcKey& ec_key =
      internal::GetEcKey(EllipticCurveType::NIST_P256);
  auto verifier_result = EcdsaVerifyBoringSsl::New(
      ec_key, HashType::SHA1, EcdsaSignatureEncoding::IEEE_P1363);
  EXPECT_THAT(verifier_result, Not(IsOk()));
}

static absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> GetVerifier(
    const google::protobuf::Value& test_group,
    subtle::EcdsaSignatureEncoding encoding) {
  const auto& test_group_fields = test_group.struct_value().fields();
  const auto& key_fields =
      test_group_fields.at("publicKey").struct_value().fields();
  std::string pub_x = GetIntegerFromHexValue(key_fields.at("wx"));
  std::string pub_y = GetIntegerFromHexValue(key_fields.at("wy"));
  EllipticCurveType curve =
      GetEllipticCurveTypeFromValue(key_fields.at("curve"));
  HashType md = GetHashTypeFromValue(test_group_fields.at("sha"));

  EcdsaParameters::CurveType curve_type;
  switch (curve) {
    case EllipticCurveType::NIST_P256:
      curve_type = EcdsaParameters::CurveType::kNistP256;
      break;
    case EllipticCurveType::NIST_P384:
      curve_type = EcdsaParameters::CurveType::kNistP384;
      break;
    case EllipticCurveType::NIST_P521:
      curve_type = EcdsaParameters::CurveType::kNistP521;
      break;
    default:
      return absl::InvalidArgumentError("Unsupported curve type");
  }

  EcdsaParameters::HashType hash_type;
  switch (md) {
    case HashType::SHA256:
      hash_type = EcdsaParameters::HashType::kSha256;
      break;
    case HashType::SHA384:
      hash_type = EcdsaParameters::HashType::kSha384;
      break;
    case HashType::SHA512:
      hash_type = EcdsaParameters::HashType::kSha512;
      break;
    default:
      return absl::InvalidArgumentError("Unsupported hash type");
  }

  EcdsaParameters::SignatureEncoding sig_encoding;
  switch (encoding) {
    case subtle::EcdsaSignatureEncoding::DER:
      sig_encoding = EcdsaParameters::SignatureEncoding::kDer;
      break;
    case subtle::EcdsaSignatureEncoding::IEEE_P1363:
      sig_encoding = EcdsaParameters::SignatureEncoding::kIeeeP1363;
      break;
    default:
      return absl::InvalidArgumentError("Unsupported signature encoding");
  }

  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(curve_type)
          .SetHashType(hash_type)
          .SetSignatureEncoding(sig_encoding)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  if (!params.ok()) {
    return params.status();
  }

  ABSL_ASSIGN_OR_RETURN(
      EcdsaPublicKey public_key,
      EcdsaPublicKey::Create(
          *params, EcPoint(BigInteger(pub_x), BigInteger(pub_y)),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));

  absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> result =
      EcdsaVerifyBoringSsl::New(public_key);
  if (!result.ok()) {
    std::cout << "Failed: " << result.status() << "\n";
  }
  return result;
}

// Tests signature verification using the test vectors in the specified file.
// allow_skipping determines whether it is OK to skip a test because
// a verfier cannot be constructed. This option can be used for
// if a file contains test vectors that are not necessarily supported
// by tink.
bool TestSignatures(const std::string& filename,
                    int expected_skipped_test_groups,
                    subtle::EcdsaSignatureEncoding encoding) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(filename);
  ABSL_CHECK_OK(parsed_input.status());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  int passed_tests = 0;
  int failed_tests = 0;
  int skipped_test_groups = 0;
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    auto verifier_result = GetVerifier(test_group, encoding);
    if (!verifier_result.ok()) {
      ++skipped_test_groups;
      continue;
    }
    auto verifier = std::move(verifier_result.value());
    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      std::string expected = test_fields.at("result").string_value();
      std::string msg = GetBytesFromHexValue(test_fields.at("msg"));
      std::string sig = GetBytesFromHexValue(test_fields.at("sig"));
      std::string id = absl::StrCat(test_fields.at("tcId").number_value(), " ",
                                    test_fields.at("comment").string_value());
      auto status = verifier->Verify(sig, msg);
      if (expected == "valid") {
        if (status.ok()) {
          ++passed_tests;
        } else {
          ++failed_tests;
          ADD_FAILURE() << "Valid signature not verified:" << id
                        << " status:" << status;
        }
      } else if (expected == "invalid") {
        if (!status.ok()) {
          ++passed_tests;
        } else {
          ++failed_tests;
          ADD_FAILURE() << "Invalid signature verified:" << id;
        }
      } else if (expected == "acceptable") {
        // The validity of the signature is undefined. Hence the test passes
        // but we log the result since we might still want to know if the
        // library is strict or forgiving.
        ++passed_tests;
        std::cout << "Acceptable signature:" << id << ":" << status;
      } else {
        ++failed_tests;
        ADD_FAILURE() << "Invalid field result:" << expected;
      }
    }
  }
  int num_tests = parsed_input->fields().at("numberOfTests").number_value();
  ABSL_CHECK_EQ(skipped_test_groups, expected_skipped_test_groups);
  std::cout << "total number of tests: " << num_tests;
  std::cout << "number of tests passed:" << passed_tests;
  std::cout << "number of tests failed:" << failed_tests;
  return failed_tests == 0;
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP256) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp256r1_sha256_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP384) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp384r1_sha512_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP521) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp521r1_sha512_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::DER));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP256WithIeeeP1363Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp256r1_sha256_p1363_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::IEEE_P1363));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP384WithIeeeP1363Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp384r1_sha512_p1363_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::IEEE_P1363));
}

TEST_F(EcdsaVerifyBoringSslTest, WycheproofCurveP521WithIeeeP1363Encoding) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("ecdsa_secp521r1_sha512_p1363_test.json",
                             /*expected_skipped_test_groups=*/0,
                             subtle::EcdsaSignatureEncoding::IEEE_P1363));
}

// FIPS-only mode test
TEST_F(EcdsaVerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const internal::EcKey& ec_key_256 =
      internal::GetEcKey(EllipticCurveType::NIST_P256);
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key_256, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  const internal::EcKey& ec_key_384 =
      internal::GetEcKey(EllipticCurveType::NIST_P384);
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key_384, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));

  const internal::EcKey& ec_key_521 =
      internal::GetEcKey(EllipticCurveType::NIST_P521);
  EXPECT_THAT(EcdsaVerifyBoringSsl::New(ec_key_521, HashType::SHA256,
                                        EcdsaSignatureEncoding::DER)
                  .status(),
              StatusIs(absl::StatusCode::kInternal));
}

using EcdsaVerifyBoringSslTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(EcdsaVerifyBoringSslTestVectorTest, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const EcdsaPrivateKey* typed_key =
      dynamic_cast<const EcdsaPrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(EcdsaVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(EcdsaVerifyBoringSslTestVectorTest, DifferentMessageDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const EcdsaPrivateKey* typed_key =
      dynamic_cast<const EcdsaPrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(EcdsaVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      EcdsaVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(EcdsaVerifyBoringSslTestVectorTest,
                         EcdsaVerifyBoringSslTestVectorTest,
                         testing::ValuesIn(internal::CreateEcdsaTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
