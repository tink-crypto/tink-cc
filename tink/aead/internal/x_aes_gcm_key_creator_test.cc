// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, embodiment or
// conditions of any kind, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/x_aes_gcm_key_creator.h"

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
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::TestWithParam;

const XAesGcmParameters& XAesGcm8ByteSaltTinkParameters() {
  static const absl::NoDestructor<XAesGcmParameters> kParameters([] {
    absl::StatusOr<XAesGcmParameters> parameters =
        XAesGcmParameters::Create(XAesGcmParameters::Variant::kTink, 8);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const XAesGcmParameters& XAesGcm8ByteSaltNoPrefixParameters() {
  static const absl::NoDestructor<XAesGcmParameters> kParameters([] {
    absl::StatusOr<XAesGcmParameters> parameters =
        XAesGcmParameters::Create(XAesGcmParameters::Variant::kNoPrefix, 8);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const XAesGcmParameters& XAesGcm12ByteSaltTinkParameters() {
  static const absl::NoDestructor<XAesGcmParameters> kParameters([] {
    absl::StatusOr<XAesGcmParameters> parameters =
        XAesGcmParameters::Create(XAesGcmParameters::Variant::kTink, 12);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const XAesGcmParameters& XAesGcm12ByteSaltNoPrefixParameters() {
  static const absl::NoDestructor<XAesGcmParameters> kParameters([] {
    absl::StatusOr<XAesGcmParameters> parameters =
        XAesGcmParameters::Create(XAesGcmParameters::Variant::kNoPrefix, 12);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

struct TestVector {
  std::string name;
  const XAesGcmParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class XAesGcmKeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(XAesGcmKeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateXAesGcmKey(test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  XAesGcmKey* x_aes_gcm_key = dynamic_cast<XAesGcmKey*>(key->get());
  ASSERT_NE(x_aes_gcm_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(x_aes_gcm_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(x_aes_gcm_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(x_aes_gcm_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(x_aes_gcm_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(32));

  EXPECT_EQ(x_aes_gcm_key->GetOutputPrefix(), test_vector.expected_prefix);
}

TEST(XAesGcmKeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateXAesGcmKey(XAesGcm8ByteSaltTinkParameters(), std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    XAesGcmKeyCreatorTest, XAesGcmKeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"XAesGcm8ByteSaltTinkParameters",
         /*parameters=*/XAesGcm8ByteSaltTinkParameters(),
         /*id_requirement=*/1,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x01})},
        {/*name=*/"XAesGcm8ByteSaltNoPrefixParameters",
         /*parameters=*/XAesGcm8ByteSaltNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"XAesGcm12ByteSaltTinkParameters",
         /*parameters=*/XAesGcm12ByteSaltTinkParameters(),
         /*id_requirement=*/2,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x02})},
        {/*name=*/"XAesGcm12ByteSaltNoPrefixParameters",
         /*parameters=*/XAesGcm12ByteSaltNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<XAesGcmKeyCreatorTest::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
