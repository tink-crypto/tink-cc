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

#include "tink/aead/internal/aes_eax_key_creator.h"

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
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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

const AesEaxParameters& Aes128EaxTinkParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(16)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesEaxParameters& Aes128EaxNoPrefixParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(12)
            .SetKeySizeInBytes(16)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesEaxParameters& Aes192EaxTinkParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(16)
            .SetKeySizeInBytes(24)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesEaxParameters& Aes192EaxNoPrefixParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(16)
            .SetKeySizeInBytes(24)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesEaxParameters& Aes256EaxTinkParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(16)
            .SetKeySizeInBytes(32)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const AesEaxParameters& Aes256EaxNoPrefixParameters() {
  static const absl::NoDestructor<AesEaxParameters> kParameters([] {
    absl::StatusOr<AesEaxParameters> parameters =
        AesEaxParameters::Builder()
            .SetIvSizeInBytes(16)
            .SetKeySizeInBytes(32)
            .SetTagSizeInBytes(16)
            .SetVariant(AesEaxParameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

struct TestVector {
  std::string name;
  const AesEaxParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class AesEaxKeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(AesEaxKeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesEaxKey(test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  AesEaxKey* aes_eax_key = dynamic_cast<AesEaxKey*>(key->get());
  ASSERT_NE(aes_eax_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(aes_eax_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(aes_eax_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(aes_eax_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(aes_eax_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(test_vector.parameters.GetKeySizeInBytes()));

  EXPECT_EQ(aes_eax_key->GetOutputPrefix(), test_vector.expected_prefix);
}

TEST(AesEaxKeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateAesEaxKey(Aes128EaxTinkParameters(), std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    AesEaxKeyCreatorTest, AesEaxKeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"Aes128EaxTinkParameters",
         /*parameters=*/Aes128EaxTinkParameters(),
         /*id_requirement=*/1,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x01})},
        {/*name=*/"Aes128EaxNoPrefixParameters",
         /*parameters=*/Aes128EaxNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes192EaxTinkParameters",
         /*parameters=*/Aes192EaxTinkParameters(),
         /*id_requirement=*/2,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x02})},
        {/*name=*/"Aes192EaxNoPrefixParameters",
         /*parameters=*/Aes192EaxNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes256EaxTinkParameters",
         /*parameters=*/Aes256EaxTinkParameters(),
         /*id_requirement=*/3,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x03})},
        {/*name=*/"Aes256EaxNoPrefixParameters",
         /*parameters=*/Aes256EaxNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<AesEaxKeyCreatorTest::ParamType>& info) {
      return info.param.name;
    });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
