// Copyright 2018 Google LLC
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

#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"

#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
class RsaSsaPkcs1VerifyBoringSslTest : public ::testing::Test {};

namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::GetHashTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::GetIntegerFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::testing::Not;
using ::testing::NotNull;

internal::RsaPublicKey ToRsaPublicKey(const RsaSsaPkcs1PublicKey& key) {
  internal::RsaPublicKey public_key;
  public_key.n = std::string(key.GetModulus(GetPartialKeyAccess()).GetValue());
  public_key.e =
      std::string(key.GetParameters().GetPublicExponent().GetValue());
  return public_key;
}

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  HashType sig_hash;
};

const NistTestVector& GetNistTestVector() {
  static const absl::NoDestructor<NistTestVector> nist_test_vector([] {
    return NistTestVector{
        test::HexDecodeOrDie(
            "c47abacc2a84d56f3614d92fd62ed36ddde459664b9301dcd1d61781cfcc026bcb"
            "2399bee7e75681a80b7bf500e2d08ceae1c42ec0b707927f2b2fe92ae852087d25"
            "f1d260cc74905ee5f9b254ed05494a9fe06732c3680992dd6f0dc634568d11542a"
            "705f83ae96d2a49763d5fbb24398edf3702bc94bc168190166492b8671de874bb9"
            "cecb058c6c8344aa8c93754d6effcd44a41ed7de0a9dcd9144437f212b18881d04"
            "2d331a4618a9e630ef9bb66305e4fdf8f0391b3b2313fe549f0189ff968b92f33c"
            "266a4bc2cffc897d1937eeb9e406f5d0eaa7a14782e76af3fce98f54ed237b4a04"
            "a4159a5f6250a296a902880204e61d891c4da29f2d65f34cbb"),
        test::HexDecodeOrDie("49d2a1"),
        test::HexDecodeOrDie(
            "95123c8d1b236540b86976a11cea31f8bd4e6c54c235147d20ce722b03a6ad756f"
            "bd918c27df8ea9ce3104444c0bbe877305bc02e35535a02a58dcda306e632ad30b"
            "3dc3ce0ba97fdf46ec192965dd9cd7f4a71b02b8cba3d442646eeec4af590824ca"
            "98d74fbca934d0b6867aa1991f3040b707e806de6e66b5934f05509bea"),
        test::HexDecodeOrDie(
            "51265d96f11ab338762891cb29bf3f1d2b3305107063f5f3245af376dfcc7027d3"
            "9365de70a31db05e9e10eb6148cb7f6425f0c93c4fb0e2291adbd22c77656afc19"
            "6858a11e1c670d9eeb592613e69eb4f3aa501730743ac4464486c7ae68fd509e89"
            "6f63884e9424f69c1c5397959f1e52a368667a598a1fc90125273d9341295d2f8e"
            "1cc4969bf228c860e07a3546be2eeda1cde48ee94d062801fe666e4a7ae8cb9cd7"
            "9262c017b081af874ff00453ca43e34efdb43fffb0bb42a4e2d32a5e5cc9e8546a"
            "221fe930250e5f5333e0efe58ffebf19369a3b8ae5a67f6a048bc9ef915bda2516"
            "0729b508667ada84a0c27e7e26cf2abca413e5e4693f4a9405"),
        HashType::SHA256};
  }());
  return *nist_test_vector;
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, BasicVerify) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const NistTestVector& nist_test_vector = GetNistTestVector();
  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{nist_test_vector.sig_hash};

  auto verifier_result = RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params);
  ASSERT_THAT(verifier_result, IsOk());
  auto verifier = std::move(verifier_result.value());
  auto status =
      verifier->Verify(nist_test_vector.signature, nist_test_vector.message);
  EXPECT_THAT(status, IsOk()) << internal::GetSslErrors();
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, NewErrors) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const NistTestVector& nist_test_vector = GetNistTestVector();
  internal::RsaPublicKey nist_pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params nist_params{nist_test_vector.sig_hash};
  internal::RsaPublicKey small_pub_key{std::string("\x23"), std::string("\x3")};
  internal::RsaSsaPkcs1Params sha1_hash_params{HashType::SHA1};

  {  // Small modulus.
    auto result = RsaSsaPkcs1VerifyBoringSsl::New(small_pub_key, nist_params);
    EXPECT_THAT(result, Not(IsOk()));
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "only modulus size >= 2048-bit is supported",
                        std::string(result.status().message()));
  }

  {  // Use SHA1 for digital signature.
    auto result =
        RsaSsaPkcs1VerifyBoringSsl::New(nist_pub_key, sha1_hash_params);
    EXPECT_THAT(result, Not(IsOk()));
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        std::string(result.status().message()));
  }
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, SizeIsWithinLimit) {
  EXPECT_LE(sizeof(RsaSsaPkcs1VerifyBoringSsl), 112);
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, Modification) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }

  const NistTestVector& nist_test_vector = GetNistTestVector();
  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{nist_test_vector.sig_hash};

  auto verifier_result = RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params);
  ASSERT_THAT(verifier_result, IsOk());
  auto verifier = std::move(verifier_result.value());
  // Modify the message.
  for (std::size_t i = 0; i < nist_test_vector.message.length(); i++) {
    std::string modified_message = nist_test_vector.message;
    modified_message[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(nist_test_vector.signature, modified_message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
  // Modify the signature.
  for (std::size_t i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string modified_signature = nist_test_vector.signature;
    modified_signature[i / 8] ^= 1 << (i % 8);
    auto status =
        verifier->Verify(modified_signature, nist_test_vector.message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
  // Truncate the signature.
  for (std::size_t i = 0; i < nist_test_vector.signature.length(); i++) {
    std::string truncated_signature(nist_test_vector.signature, 0, i);
    auto status =
        verifier->Verify(truncated_signature, nist_test_vector.message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
}

static absl::StatusOr<std::unique_ptr<RsaSsaPkcs1VerifyBoringSsl>> GetVerifier(
    const google::protobuf::Value& test_group) {
  auto test_group_fields = test_group.struct_value().fields();

  internal::RsaPublicKey key;
  const auto& public_key_fields =
      test_group_fields.at("publicKey").struct_value().fields();
  key.n = GetIntegerFromHexValue(public_key_fields.at("modulus"));
  key.e = GetIntegerFromHexValue(public_key_fields.at("publicExponent"));

  HashType md = GetHashTypeFromValue(test_group_fields.at("sha"));
  internal::RsaSsaPkcs1Params params;
  params.hash_type = md;

  auto result = RsaSsaPkcs1VerifyBoringSsl::New(key, params);
  if (!result.ok()) {
    std::cout << "Failed: " << result.status() << "\n";
  }
  return result;
}

// Tests signature verification using the test vectors in the specified file.
bool TestSignatures(const std::string& filename) {
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(filename);
  ABSL_CHECK_OK(parsed_input.status());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  int passed_tests = 0;
  int failed_tests = 0;
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    auto test_group_fields = test_group.struct_value().fields();
    auto verifier_result = GetVerifier(test_group);
    ABSL_CHECK_OK(verifier_result.status());
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
  int num_tests =
      (int)parsed_input->fields().at("numberOfTests").number_value();
  ABSL_CHECK_EQ(num_tests, passed_tests + failed_tests);
  std::cout << "total number of tests: " << num_tests;
  std::cout << "number of tests passed:" << passed_tests;
  std::cout << "number of tests failed:" << failed_tests;
  return failed_tests == 0;
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs12048SHA256) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_2048_sha256_test.json"));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs13072SHA256) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_3072_sha256_test.json"));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs13072SHA512) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_3072_sha512_test.json"));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, WycheproofRsaPkcs14096SHA512) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  ASSERT_TRUE(TestSignatures("rsa_signature_4096_sha512_test.json"));
}

// FIPS-only mode test
TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }

  const NistTestVector& nist_test_vector = GetNistTestVector();
  internal::RsaPublicKey pub_key{nist_test_vector.n, nist_test_vector.e};
  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(pub_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestAllowedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  const internal::SignatureTestVector& test_vector =
      internal::Create3072BitsTestVector();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  internal::RsaPublicKey public_key = ToRsaPublicKey(typed_key->GetPublicKey());

  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};
  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(public_key, params).status(),
              IsOk());
}

TEST_F(RsaSsaPkcs1VerifyBoringSslTest, TestRestrictedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  internal::RsaPublicKey public_key;
  // Any arbitrary 4096-bit modulus is sufficient here.
  public_key.n = std::string(512, '\x80');
  public_key.e = "\x01\x00\x01";
  internal::RsaSsaPkcs1Params params{/*sig_hash=*/HashType::SHA256};

  EXPECT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(public_key, params).status(),
              StatusIs(absl::StatusCode::kInternal));
}

using RsaSsaPkcs1VerifyBoringSslTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(RsaSsaPkcs1VerifyBoringSslTestVectorTest, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(RsaSsaPkcs1VerifyBoringSslTestVectorTest,
       DifferentMessageDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPkcs1VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1VerifyBoringSslTestVectorTest,
    RsaSsaPkcs1VerifyBoringSslTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPkcs1TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
