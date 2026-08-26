// Copyright 2019 Google LLC
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

#include "tink/subtle/ed25519_verify_boringssl.h"

#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Test;
using ::testing::TestWithParam;

// Non-FIPS tests.
class Ed25519VerifyBoringSslTest : public Test {
 private:
  void SetUp() override {
    if (IsFipsModeEnabled()) {
      GTEST_SKIP() << "Test assumes kOnlyUseFips is false.";
    }
  }
};

TEST_F(Ed25519VerifyBoringSslTest, InvalidPublicKey) {
  // Null public key.
  const absl::string_view null_public_key;
  EXPECT_THAT(Ed25519VerifyBoringSsl::New(null_public_key).status(),
              Not(IsOk()));

  for (int keysize = 0; keysize < 128; keysize++) {
    if (keysize == internal::Ed25519KeyPubKeySize()) {
      // Valid key size.
      continue;
    }
    std::string key(keysize, 'x');
    EXPECT_THAT(Ed25519VerifyBoringSsl::New(key), Not(IsOk()));
  }
}

// Using the test vector with an empty message, this makes sure verification
// succeeds passing an empty string_view, an empty string and a
// default-constructed string_view.
TEST_F(Ed25519VerifyBoringSslTest, MessageEmptyVersusNullStringView) {
  const internal::SignatureTestVector& test_vector =
      internal::CreateEd25519EmptyMessageTestVector();
  const Ed25519PrivateKey* typed_key = dynamic_cast<const Ed25519PrivateKey*>(
      test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  // Message is a null string_view.
  const absl::string_view kEmptyStringView;
  EXPECT_THAT((*verifier)->Verify(test_vector.signature, kEmptyStringView),
              IsOk());

  // Message is an empty string.
  const std::string kEmptyStr = "";
  EXPECT_THAT((*verifier)->Verify(test_vector.signature, kEmptyStr), IsOk());

  // Message is a default constructed string_view.
  EXPECT_THAT((*verifier)->Verify(test_vector.signature, absl::string_view()),
              IsOk());
}

static absl::StatusOr<std::unique_ptr<PublicKeyVerify>> GetVerifier(
    const google::protobuf::Value& test_group) {
  const google::protobuf::Value& key =
      test_group.struct_value().fields().at("publicKey");
  std::string public_key =
      GetBytesFromHexValue(key.struct_value().fields().at("pk"));
  auto result = Ed25519VerifyBoringSsl::New(public_key);
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

TEST_F(Ed25519VerifyBoringSslTest, WycheproofCurve25519) {
  ASSERT_TRUE(TestSignatures("ed25519_test.json"));
}

TEST(Ed25519VerifyBoringSslFipsTest, testFipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  constexpr absl::string_view kPublicKey =
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
  // Create a new signer.
  EXPECT_THAT(
      Ed25519VerifyBoringSsl::New(test::HexDecodeOrDie(kPublicKey)).status(),
      StatusIs(absl::StatusCode::kInternal));
}

using Ed25519VerifyBoringSslTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(Ed25519VerifyBoringSslTestVectorTest, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled()) {
    // Users wants FIPS, but Ed25519 is not FIPS.
    ASSERT_THAT(Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(Ed25519VerifyBoringSslTestVectorTest, DifferentMessageDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled()) {
    // Users wants FIPS, but Ed25519 is not FIPS.
    ASSERT_THAT(Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      Not(IsOk()));
}

TEST_P(Ed25519VerifyBoringSslTestVectorTest,
       DifferentFirstByteSignatureDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const Ed25519PrivateKey* typed_key =
      dynamic_cast<const Ed25519PrivateKey*>(param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled()) {
    // Users wants FIPS, but Ed25519 is not FIPS.
    ASSERT_THAT(Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      Ed25519VerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  std::string modified_signature = param.signature;
  modified_signature[0] ^= 1;
  EXPECT_THAT((*verifier)->Verify(modified_signature, param.message),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    Ed25519VerifyBoringSslTestVectorTest, Ed25519VerifyBoringSslTestVectorTest,
    testing::ValuesIn(internal::CreateEd25519TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
