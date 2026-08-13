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

#include "tink/signature/internal/ml_dsa_sign_prehash_boringssl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/testing/wycheproof_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/ml_dsa_key_creator.h"
#include "tink/signature/internal/ml_dsa_prehash_boringssl.h"
#include "tink/signature/internal/ml_dsa_verify_boringssl.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/prehash.h"
#include "tink/signature/sign_prehash.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  MlDsaParameters::Instance instance;
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string expected_output_prefix;
};

using MlDsaSignPrehashBoringSslTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaSignPrehashBoringSslTestSuite, MlDsaSignPrehashBoringSslTest,
    Values(TestCase{MlDsaParameters::Instance::kMlDsa44,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030400, ""},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030400, ""},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kNoPrefixWithPrehashId,
                    0x02030400, ""}));

TEST_P(MlDsaSignPrehashBoringSslTest, SignPrehashWithInvalidPrefixFails) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      NewMlDsaSignPrehashBoringSsl(**private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  std::string message = "message for prehash signing";
  absl::StatusOr<std::string> prehash = (*prehasher)->Compute(message);
  ASSERT_THAT(prehash, IsOk());

  // Mutate prehash prefix
  std::string invalid_prehash = *prehash;
  invalid_prehash[1] ^= 0xff;

  EXPECT_THAT((*prehash_signer)->Sign(invalid_prehash).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(MlDsaSignPrehashBoringSslTest, SignPrehashWithInvalidLengthFails) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      NewMlDsaSignPrehashBoringSsl(**private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  EXPECT_THAT((*prehash_signer)->Sign("short_prehash").status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(MlDsaSignPrehashBoringSslNonParamTest, AcceptVariants) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  // Test kTink is accepted
  auto tink_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(tink_params, IsOk());
  auto tink_key = CreateMlDsaKey(*tink_params, 0x01020304);
  ASSERT_THAT(tink_key, IsOk());
  EXPECT_THAT(NewMlDsaSignPrehashBoringSsl(**tink_key).status(), IsOk());

  // Test kNoPrefix is accepted
  auto noprefix_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(noprefix_params, IsOk());
  auto noprefix_key = CreateMlDsaKey(*noprefix_params, std::nullopt);
  ASSERT_THAT(noprefix_key, IsOk());
  EXPECT_THAT(NewMlDsaSignPrehashBoringSsl(**noprefix_key).status(), IsOk());
}

using MlDsaSignPrehashRawTest = TestWithParam<MlDsaParameters::Instance>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaSignPrehashRawTestSuite, MlDsaSignPrehashRawTest,
    Values(MlDsaParameters::Instance::kMlDsa44,
           MlDsaParameters::Instance::kMlDsa65,
           MlDsaParameters::Instance::kMlDsa87));

TEST_P(MlDsaSignPrehashRawTest, SignVerifyFlowWithRawKeyWorks) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  MlDsaParameters::Instance instance = GetParam();

  absl::StatusOr<MlDsaParameters> key_parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*key_parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
      NewMlDsaPrehashBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(prehasher, IsOk());

  absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
      NewMlDsaSignPrehashBoringSsl(**private_key);
  ASSERT_THAT(prehash_signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      NewMlDsaVerifyBoringSsl((*private_key)->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message = "message for prehash signing";
  absl::StatusOr<std::string> prehash = (*prehasher)->Compute(message);
  ASSERT_THAT(prehash, IsOk());

  absl::StatusOr<std::string> signature = (*prehash_signer)->Sign(*prehash);
  ASSERT_THAT(signature, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, "wrong_message"), Not(IsOk()));
}

// Wycheproof test vectors from mldsa_{44,65,87}_sign_seed_test.json.
struct WycheproofTestCase {
  MlDsaParameters::Instance instance;
  std::string filename;
};

using MlDsaSignPrehashWycheproofTest = TestWithParam<WycheproofTestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaSignPrehashWycheproofTestSuite, MlDsaSignPrehashWycheproofTest,
    Values(WycheproofTestCase{MlDsaParameters::Instance::kMlDsa44,
                              "mldsa_44_sign_seed_test.json"},
           WycheproofTestCase{MlDsaParameters::Instance::kMlDsa65,
                              "mldsa_65_sign_seed_test.json"},
           WycheproofTestCase{MlDsaParameters::Instance::kMlDsa87,
                              "mldsa_87_sign_seed_test.json"}));

TEST_P(MlDsaSignPrehashWycheproofTest, PrehashSignVerifyWycheproofTestVectors) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Test is skipped if kOnlyUseFips but BoringCrypto is unavailable.";
  }

  WycheproofTestCase test_case = GetParam();

  absl::StatusOr<google::protobuf::Struct> parsed_input =
      wycheproof_testing::ReadTestVectorsV1(test_case.filename);
  ASSERT_THAT(parsed_input, IsOk());

  absl::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kNoPrefixWithPrehashId);
  ASSERT_THAT(key_parameters, IsOk());

  const google::protobuf::Value& test_groups =
      parsed_input->fields().at("testGroups");
  for (const google::protobuf::Value& test_group :
       test_groups.list_value().values()) {
    std::string private_seed_bytes = wycheproof_testing::GetBytesFromHexValue(
        test_group.struct_value().fields().at("privateSeed"));
    RestrictedData private_seed(private_seed_bytes,
                               InsecureSecretKeyAccess::Get());
    constexpr uint32_t kKeyId = 0x01020304;
    absl::StatusOr<MlDsaPrivateKey> private_key =
        MlDsaPrivateKey::Create(*key_parameters, private_seed,
                                /*id_requirement=*/kKeyId,
                                GetPartialKeyAccess());
    ASSERT_THAT(private_key, IsOk());

    absl::StatusOr<std::unique_ptr<Prehash>> prehasher =
        NewMlDsaPrehashBoringSsl(private_key->GetPublicKey());
    ASSERT_THAT(prehasher, IsOk());

    absl::StatusOr<std::unique_ptr<SignPrehash>> prehash_signer =
        NewMlDsaSignPrehashBoringSsl(*private_key);
    ASSERT_THAT(prehash_signer, IsOk());

    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        NewMlDsaVerifyBoringSsl(private_key->GetPublicKey());
    ASSERT_THAT(verifier, IsOk());

    for (const google::protobuf::Value& test :
         test_group.struct_value().fields().at("tests").list_value().values()) {
      auto test_fields = test.struct_value().fields();
      std::string msg =
          wycheproof_testing::GetBytesFromHexValue(test_fields.at("msg"));

      absl::StatusOr<std::string> prehash = (*prehasher)->Compute(msg);
      ASSERT_THAT(prehash, IsOk());

      absl::StatusOr<std::string> signature = (*prehash_signer)->Sign(*prehash);
      ASSERT_THAT(signature, IsOk());

      EXPECT_THAT((*verifier)->Verify(*signature, msg), IsOk());
    }
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
