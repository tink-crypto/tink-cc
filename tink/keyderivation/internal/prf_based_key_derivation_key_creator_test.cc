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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyderivation/internal/prf_based_key_derivation_test_vectors.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/rtti.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

const PrfBasedKeyDerivationParameters&
HkdfSha256XChaCha20Poly1305TinkParameters() {
  static const absl::NoDestructor<PrfBasedKeyDerivationParameters> kParameters(
      [] {
        absl::StatusOr<HkdfPrfParameters> prf_parameters =
            HkdfPrfParameters::Create(/*key_size_in_bytes=*/32,
                                      HkdfPrfParameters::HashType::kSha256,
                                      /*salt=*/std::nullopt);
        ABSL_CHECK_OK(prf_parameters);
        absl::StatusOr<XChaCha20Poly1305Parameters> derived_parameters =
            XChaCha20Poly1305Parameters::Create(
                XChaCha20Poly1305Parameters::Variant::kTink);
        ABSL_CHECK_OK(derived_parameters);
        absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
            PrfBasedKeyDerivationParameters::Builder()
                .SetPrfParameters(*prf_parameters)
                .SetDerivedKeyParameters(*derived_parameters)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParameters;
}

const PrfBasedKeyDerivationParameters&
HkdfSha256SaltXChaCha20Poly1305NoPrefixParameters() {
  static const absl::NoDestructor<PrfBasedKeyDerivationParameters> kParameters(
      [] {
        absl::StatusOr<HkdfPrfParameters> prf_parameters =
            HkdfPrfParameters::Create(/*key_size_in_bytes=*/22,
                                      HkdfPrfParameters::HashType::kSha256,
                                      /*salt=*/"salt");
        ABSL_CHECK_OK(prf_parameters);
        absl::StatusOr<XChaCha20Poly1305Parameters> derived_parameters =
            XChaCha20Poly1305Parameters::Create(
                XChaCha20Poly1305Parameters::Variant::kNoPrefix);
        ABSL_CHECK_OK(derived_parameters);
        absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
            PrfBasedKeyDerivationParameters::Builder()
                .SetPrfParameters(*prf_parameters)
                .SetDerivedKeyParameters(*derived_parameters)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParameters;
}

struct TestCase {
  std::string name;
  const PrfBasedKeyDerivationParameters& parameters;
  std::optional<int> id_requirement;
};

using PrfBasedKeyDerivationKeyCreatorParameterizedTest =
    TestWithParam<TestCase>;

TEST_P(PrfBasedKeyDerivationKeyCreatorParameterizedTest, CreateKeyWorks) {
  const TestCase& test_case = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key = CreatePrfBasedKeyDerivationKey(
      test_case.parameters, test_case.id_requirement);
  ASSERT_THAT(key, IsOk());

  const auto* derivation_key =
      DynamicCast<const PrfBasedKeyDerivationKey*>(key->get());
  ASSERT_NE(derivation_key, nullptr);
  EXPECT_THAT(derivation_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(derivation_key->GetParameters(), Eq(test_case.parameters));

  const auto* hkdf_prf_key =
      DynamicCast<const HkdfPrfKey*>(&derivation_key->GetPrfKey());
  ASSERT_NE(hkdf_prf_key, nullptr);
  EXPECT_EQ(hkdf_prf_key->GetParameters(),
            test_case.parameters.GetPrfParameters());
}

TEST_P(PrfBasedKeyDerivationKeyCreatorParameterizedTest,
       CreateKeyTwiceYieldsDifferentKeys) {
  const TestCase& test_case = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key1 = CreatePrfBasedKeyDerivationKey(
      test_case.parameters, test_case.id_requirement);
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 = CreatePrfBasedKeyDerivationKey(
      test_case.parameters, test_case.id_requirement);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(PrfBasedKeyDerivationKeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const TestCase& test_case = GetParam();
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddKeyCreator<PrfBasedKeyDerivationParameters>(
          CreatePrfBasedKeyDerivationKey, key_creator_config),
      IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      test_case.parameters, test_case.id_requirement, key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(test_case.parameters));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
}

INSTANTIATE_TEST_SUITE_P(
    PrfBasedKeyDerivationKeyCreatorParameterizedTests,
    PrfBasedKeyDerivationKeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"HkdfSha256XChaCha20Poly1305Tink",
         /*parameters=*/HkdfSha256XChaCha20Poly1305TinkParameters(),
         /*id_requirement=*/0x02030400},
        {/*name=*/"HkdfSha256SaltXChaCha20Poly1305NoPrefix",
         /*parameters=*/HkdfSha256SaltXChaCha20Poly1305NoPrefixParameters(),
         /*id_requirement=*/std::nullopt},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(PrfBasedKeyDerivationKeyCreatorTest,
     CreateKeyTinkWithoutIdRequirementFails) {
  EXPECT_THAT(CreatePrfBasedKeyDerivationKey(
                  HkdfSha256XChaCha20Poly1305TinkParameters(), std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedKeyDerivationKeyCreatorTest,
     CreateKeyNoPrefixWithIdRequirementFails) {
  EXPECT_THAT(CreatePrfBasedKeyDerivationKey(
                  HkdfSha256SaltXChaCha20Poly1305NoPrefixParameters(), 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedKeyDerivationKeyCreatorTest,
     CreateKeyWithUnsupportedPrfParametersFails) {
  const PrfBasedKeyDerivationKey& unsupported_key =
      GetPrfBasedKeyDerivationAesCmacTestVector().key;
  EXPECT_THAT(
      CreatePrfBasedKeyDerivationKey(unsupported_key.GetParameters(),
                                     unsupported_key.GetIdRequirement()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
