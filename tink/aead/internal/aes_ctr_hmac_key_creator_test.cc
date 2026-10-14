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

#include "tink/aead/internal/aes_ctr_hmac_key_creator.h"

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
#include "tink/aead/aes_ctr_hmac_aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
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

const AesCtrHmacAeadParameters& Aes128CtrHmacTinkParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters> kParams(
      [] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(12)
                .SetAesKeySizeInBytes(16)
                .SetHmacKeySizeInBytes(16)
                .SetTagSizeInBytes(16)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParams;
}

const AesCtrHmacAeadParameters& Aes128CtrHmacNoPrefixParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters> kParams(
      [] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(12)
                .SetAesKeySizeInBytes(16)
                .SetHmacKeySizeInBytes(16)
                .SetTagSizeInBytes(16)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParams;
}

const AesCtrHmacAeadParameters& Aes192CtrHmacTinkParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters> kParams(
      [] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(16)
                .SetAesKeySizeInBytes(24)
                .SetHmacKeySizeInBytes(32)
                .SetTagSizeInBytes(32)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha384)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParams;
}

const AesCtrHmacAeadParameters& Aes192CtrHmacNoPrefixParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters> kParams(
      [] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(16)
                .SetAesKeySizeInBytes(24)
                .SetHmacKeySizeInBytes(32)
                .SetTagSizeInBytes(32)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha384)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kParams;
}

const AesCtrHmacAeadParameters& Aes256CtrHmacTinkParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters>
      kAes256CtrHmacParameters([] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(16)
                .SetAesKeySizeInBytes(32)
                .SetHmacKeySizeInBytes(32)
                .SetTagSizeInBytes(48)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kTink)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kAes256CtrHmacParameters;
}

const AesCtrHmacAeadParameters& Aes256CtrHmacNoPrefixParameters() {
  static const absl::NoDestructor<AesCtrHmacAeadParameters>
      kAes256CtrHmacParameters([] {
        absl::StatusOr<AesCtrHmacAeadParameters> parameters =
            AesCtrHmacAeadParameters::Builder()
                .SetIvSizeInBytes(16)
                .SetAesKeySizeInBytes(32)
                .SetHmacKeySizeInBytes(32)
                .SetTagSizeInBytes(48)
                .SetHashType(AesCtrHmacAeadParameters::HashType::kSha512)
                .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
                .Build();
        ABSL_CHECK_OK(parameters);
        return *parameters;
      }());
  return *kAes256CtrHmacParameters;
}

struct TestVector {
  std::string name;
  const AesCtrHmacAeadParameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class AesCtrHmacKeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(AesCtrHmacKeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key =
      CreateAesCtrHmacKey(test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  AesCtrHmacAeadKey* aes_ctr_hmac_key =
      dynamic_cast<AesCtrHmacAeadKey*>(key->get());
  ASSERT_NE(aes_ctr_hmac_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(aes_ctr_hmac_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(aes_ctr_hmac_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(aes_ctr_hmac_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(aes_ctr_hmac_key->GetAesKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(test_vector.parameters.GetAesKeySizeInBytes()));
  EXPECT_THAT(aes_ctr_hmac_key->GetHmacKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(test_vector.parameters.GetHmacKeySizeInBytes()));
  EXPECT_EQ(aes_ctr_hmac_key->GetOutputPrefix(), test_vector.expected_prefix);
}

TEST(AesCtrHmacKeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateAesCtrHmacKey(Aes128CtrHmacTinkParameters(), std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacKeyCreatorTest, AesCtrHmacKeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"Aes128CtrHmacTinkParameters",
         /*parameters=*/Aes128CtrHmacTinkParameters(),
         /*id_requirement=*/0x01030005,
         /*expected_prefix=*/std::string({0x01, 0x01, 0x03, 0x00, 0x05})},
        {/*name=*/"Aes128CtrHmacNoPrefixParameters",
         /*parameters=*/Aes128CtrHmacNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes192CtrHmacTinkParameters",
         /*parameters=*/Aes192CtrHmacTinkParameters(),
         /*id_requirement=*/0x05060700,
         /*expected_prefix=*/std::string({0x01, 0x05, 0x06, 0x07, 0x00})},
        {/*name=*/"Aes192CtrHmacNoPrefixParameters",
         /*parameters=*/Aes192CtrHmacNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
        {/*name=*/"Aes256CtrHmacTinkParameters",
         /*parameters=*/Aes256CtrHmacTinkParameters(),
         /*id_requirement=*/0x02030400,
         /*expected_prefix=*/std::string({0x01, 0x02, 0x03, 0x04, 0x00})},
        {/*name=*/"Aes256CtrHmacNoPrefixParameters",
         /*parameters=*/Aes256CtrHmacNoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<AesCtrHmacKeyCreatorTest::ParamType>&
           info) { return info.param.name; });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
