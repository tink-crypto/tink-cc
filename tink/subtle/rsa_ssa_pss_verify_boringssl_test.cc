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

#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::TestParamInfo;
using ::testing::ValuesIn;

using ::crypto::tink::internal::wycheproof_testing::GetBytesFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::GetHashTypeFromValue;
using ::crypto::tink::internal::wycheproof_testing::GetIntegerFromHexValue;
using ::crypto::tink::internal::wycheproof_testing::ReadTestVectorsV1;

absl::StatusOr<RsaSsaPssParameters::HashType> ToParametersHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA256:
      return RsaSsaPssParameters::HashType::kSha256;
    case HashType::SHA384:
      return RsaSsaPssParameters::HashType::kSha384;
    case HashType::SHA512:
      return RsaSsaPssParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash: ", hash_type));
  }
}

absl::StatusOr<RsaSsaPssPublicKey> CreatePublicKey(
    const internal::RsaPublicKey& pub_key,
    const internal::RsaSsaPssParams& params) {
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssParameters::HashType sig_hash,
                        ToParametersHashType(params.sig_hash));
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssParameters::HashType mgf1_hash,
                        ToParametersHashType(params.mgf1_hash));
  BigInteger modulus(pub_key.n);
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssParameters parameters,
                        RsaSsaPssParameters::Builder()
                            .SetModulusSizeInBits(modulus.SizeInBytes() * 8)
                            .SetPublicExponent(BigInteger(pub_key.e))
                            .SetSigHashType(sig_hash)
                            .SetMgf1HashType(mgf1_hash)
                            .SetSaltLengthInBytes(params.salt_length)
                            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
                            .Build());
  return RsaSsaPssPublicKey::Create(parameters, modulus,
                                    /*id_requirement=*/std::nullopt,
                                    GetPartialKeyAccess());
}

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  HashType sig_hash;
  HashType mgf1_hash;
  int salt_length;
};

NistTestVector GetNistTestVector() {
  NistTestVector test_vector = {
      test::HexDecodeOrDie(
          "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf7"
          "83d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c"
          "688d81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b4427"
          "2700be527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b"
          "915248694876f3047814415164f2c660881e694b58c28038a032ad25634aad7b3917"
          "1dee368e3d59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d7"
          "7fac6cedb03ad94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2"
          "ca627ddc032fe05bbd2ff21e2db1c2f94d8b"),
      test::HexDecodeOrDie("10e43f"),
      test::HexDecodeOrDie(
          "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb"
          "1b126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22"
          "aeb40f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173"
          "187b4f09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6"),
      test::HexDecodeOrDie(
          "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc0877"
          "9a374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4c"
          "f348cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63"
          "a0c0572b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48"
          "b9f162cf6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b"
          "1dc593091db5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b"
          "1b063089ae7e2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f9"
          "5ff0111881e650ce61f251d9c3a629ef222d"),
      HashType::SHA256,
      HashType::SHA256,
      32,
  };
  return test_vector;
}

TEST(RsaSsaPssVerifyBoringSslTest, BasicVerify) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const NistTestVector kNistTestVector = GetNistTestVector();
  internal::RsaPublicKey pub_key{kNistTestVector.n, kNistTestVector.e};
  internal::RsaSsaPssParams params = {
      kNistTestVector.sig_hash,
      kNistTestVector.mgf1_hash,
      kNistTestVector.salt_length,
  };
  absl::StatusOr<RsaSsaPssPublicKey> key = CreatePublicKey(pub_key, params);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(*key);
  ASSERT_THAT(verifier, IsOk());
  absl::Status status =
      (*verifier)->Verify(kNistTestVector.signature, kNistTestVector.message);
  EXPECT_THAT(status, IsOk()) << internal::GetSslErrors();
}

TEST(RsaSsaPssVerifyBoringSslTest, Modification) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const NistTestVector kNistTestVector = GetNistTestVector();
  internal::RsaPublicKey pub_key{kNistTestVector.n, kNistTestVector.e};
  internal::RsaSsaPssParams params = {
      kNistTestVector.sig_hash,
      kNistTestVector.mgf1_hash,
      kNistTestVector.salt_length,
  };
  absl::StatusOr<RsaSsaPssPublicKey> key = CreatePublicKey(pub_key, params);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(*key);
  ASSERT_THAT(verifier, IsOk());
  // Modify the message.
  for (std::size_t i = 0; i < kNistTestVector.message.length() * 8; i++) {
    std::string modified_message = kNistTestVector.message;
    modified_message[i / 8] ^= 1 << (i % 8);
    absl::Status status =
        (*verifier)->Verify(kNistTestVector.signature, modified_message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
  // Modify the signature.
  for (std::size_t i = 0; i < kNistTestVector.signature.length() * 8; i++) {
    std::string modified_signature = kNistTestVector.signature;
    modified_signature[i / 8] ^= 1 << (i % 8);
    absl::Status status =
        (*verifier)->Verify(modified_signature, kNistTestVector.message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
  // Truncate the signature.
  for (std::size_t i = 0; i < kNistTestVector.signature.length(); i++) {
    std::string truncated_signature(kNistTestVector.signature, 0, i);
    absl::Status status =
        (*verifier)->Verify(truncated_signature, kNistTestVector.message);
    EXPECT_THAT(status, Not(IsOk())) << internal::GetSslErrors();
  }
}

TEST(RsaSsaPssVerifyBoringSslTest, VerifyWithSha384) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  const internal::SignatureTestVector& test_vector =
      internal::Create4096BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(test_vector.signature, test_vector.message),
              IsOk());

  absl::StatusOr<RsaSsaPssParameters> sha256_params =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(
              typed_key->GetParameters().GetModulusSizeInBits())
          .SetPublicExponent(typed_key->GetParameters().GetPublicExponent())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(48)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(sha256_params, IsOk());
  absl::StatusOr<RsaSsaPssPublicKey> sha256_key = RsaSsaPssPublicKey::Create(
      *sha256_params,
      typed_key->GetPublicKey().GetModulus(GetPartialKeyAccess()),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(sha256_key, IsOk());
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> sha256_verifier =
      RsaSsaPssVerifyBoringSsl::New(*sha256_key);
  ASSERT_THAT(sha256_verifier, IsOk());
  EXPECT_THAT(
      (*sha256_verifier)->Verify(test_vector.signature, test_vector.message),
      Not(IsOk()));
}

// Wycheproof test vector for RSA-SSA PSS.
struct RsaSsaPssWycheproofTestVector {
  std::string file_name;
  internal::RsaPublicKey key;
  HashType hash_type;
  HashType mgf_hash_type;
  int salt_length;
  std::string expected;
  std::string msg;
  std::string sig;
  std::string id;
  std::string comment;
};

// Reads the RSA-SSA PSS wycheproof test vectors from a given `file_name` and
// returns a vector of RsaSsaPssWycheproofTestVector.
std::vector<RsaSsaPssWycheproofTestVector> ReadWycheproofTestVectors(
    absl::string_view file_name) {
  std::vector<RsaSsaPssWycheproofTestVector> test_vectors;
  absl::StatusOr<google::protobuf::Struct> parsed_input =
      ReadTestVectorsV1(std::string(file_name));
  ABSL_CHECK_OK(parsed_input.status());
  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    auto test_group_fields = test_group.struct_value().fields();
    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      auto public_key_fields =
          test_group_fields.at("publicKey").struct_value().fields();
      test_vectors.push_back({
          /*file_name=*/std::string(file_name),
          /*key=*/
          {
              GetIntegerFromHexValue(public_key_fields.at("modulus")),
              GetIntegerFromHexValue(public_key_fields.at("publicExponent")),
          },
          /*hash_type=*/GetHashTypeFromValue(test_group_fields.at("sha")),
          /*mgf_hash_type=*/
          GetHashTypeFromValue(test_group_fields.at("mgfSha")),
          /*salt_length=*/
          static_cast<int>(test_group_fields.at("sLen").number_value()),
          /*expected=*/test.struct_value().fields().at("result").string_value(),
          /*msg=*/GetBytesFromHexValue(test_fields.at("msg")),
          /*sig=*/GetBytesFromHexValue(test_fields.at("sig")),
          /*id=*/
          absl::StrCat(test_fields.at("tcId").number_value()),
          /*comment=*/
          test_fields.at("comment").string_value(),
      });
    }
  }
  return test_vectors;
}

// Creates a verifier using the parameters in `test_vector`.
absl::StatusOr<std::unique_ptr<PublicKeyVerify>> GetVerifier(
    const RsaSsaPssWycheproofTestVector& test_vector) {
  internal::RsaSsaPssParams params = {
      test_vector.hash_type,
      test_vector.mgf_hash_type,
      test_vector.salt_length,
  };
  ABSL_ASSIGN_OR_RETURN(RsaSsaPssPublicKey key,
                        CreatePublicKey(test_vector.key, params));
  return RsaSsaPssVerifyBoringSsl::New(key);
}

using RsaSsaPssWycheproofTest =
    testing::TestWithParam<RsaSsaPssWycheproofTestVector>;

// Tests signature verification using a test vector.
TEST_P(RsaSsaPssWycheproofTest, SignatureVerify) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test not run in FIPS-only mode";
  }
  RsaSsaPssWycheproofTestVector params = GetParam();
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      GetVerifier(params);
  ASSERT_THAT(verifier, IsOk());
  absl::Status result = (*verifier)->Verify(params.sig, params.msg);

  if (params.expected == "valid") {
    EXPECT_THAT(result, IsOk());
  } else if (params.expected == "acceptable") {
    // The validity of the signature is undefined. Hence we skip the test but we
    // log the result since we might still want to know if the library is strict
    // or forgiving.
    GTEST_SKIP() << "Verification of an acceptable signature " << params.id
                 << " resulted in: " << result;
  } else {
    EXPECT_THAT(result, testing::Not(IsOk()));
  }
}

std::vector<RsaSsaPssWycheproofTestVector> GetTestParameters() {
  std::vector<RsaSsaPssWycheproofTestVector> test_vectors =
      ReadWycheproofTestVectors(
          /*file_name=*/"rsa_pss_2048_sha256_mgf1_0_test.json");
  std::vector<RsaSsaPssWycheproofTestVector> others = ReadWycheproofTestVectors(
      /*file_name=*/"rsa_pss_2048_sha256_mgf1_32_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadWycheproofTestVectors(
      /*file_name=*/"rsa_pss_3072_sha256_mgf1_32_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadWycheproofTestVectors(
      /*file_name=*/"rsa_pss_4096_sha256_mgf1_32_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  others = ReadWycheproofTestVectors(
      /*file_name=*/"rsa_pss_4096_sha512_mgf1_32_test.json");
  test_vectors.insert(test_vectors.end(), others.begin(), others.end());
  return test_vectors;
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssWycheproofTests, RsaSsaPssWycheproofTest,
    ValuesIn(GetTestParameters()),
    [](const TestParamInfo<RsaSsaPssWycheproofTest::ParamType>& info) {
      // Testcase name is partly using the test name.
      std::vector<std::string> parts =
          absl::StrSplit(info.param.file_name, ".");
      return absl::StrCat(parts[0], "_tid", info.param.id);
    });

// FIPS-only mode test
TEST(RsaSsaPssVerifyBoringSslTest, TestFipsFailWithoutBoringCrypto) {
  if (!internal::IsFipsModeEnabled() || internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test assumes kOnlyUseFips but BoringCrypto is unavailable.";
  }
  const NistTestVector kNistTestVector = GetNistTestVector();
  internal::RsaPublicKey pub_key{kNistTestVector.n, kNistTestVector.e};
  internal::RsaSsaPssParams params = {
      /*sig_hash=*/HashType::SHA256,
      /*mgf1_hash=*/HashType::SHA256,
      /*salt_length=*/32,
  };
  absl::StatusOr<RsaSsaPssPublicKey> key = CreatePublicKey(pub_key, params);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(*key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(RsaSsaPssVerifyBoringSslTest, TestAllowedFipsModuli) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips and BoringCrypto.";
  }

  const internal::SignatureTestVector& test_vector =
      internal::Create3072BitTestVector();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          test_vector.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  EXPECT_THAT(RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey()).status(),
              IsOk());
}

using RsaSsaPssVerifyBoringSslTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(RsaSsaPssVerifyBoringSslTestVectorTest, VerifySignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT((*verifier)->Verify(param.signature, param.message), IsOk());
}

TEST_P(RsaSsaPssVerifyBoringSslTestVectorTest, DifferentMessageDoesNotVerify) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPssPrivateKey* typed_key =
      dynamic_cast<const RsaSsaPssPrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    // Users wants FIPS but modulus size doesn't support FIPS
    ASSERT_THAT(RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    // Users wants FIPS, but we don't have FIPS.
    ASSERT_THAT(RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey()),
                Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      RsaSsaPssVerifyBoringSsl::New(typed_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());
  EXPECT_THAT(
      (*verifier)->Verify(param.signature, absl::StrCat(param.message, "a")),
      Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssVerifyBoringSslTestVectorTest,
    RsaSsaPssVerifyBoringSslTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPssTestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
