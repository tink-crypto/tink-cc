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

#include "tink/aead/internal/xchacha20_poly1305_key_creator.h"

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
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
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

const XChaCha20Poly1305Parameters& XChaCha20Poly1305TinkParameters() {
  static const absl::NoDestructor<XChaCha20Poly1305Parameters> kParameters([] {
    absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
        XChaCha20Poly1305Parameters::Create(
            XChaCha20Poly1305Parameters::Variant::kTink);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const XChaCha20Poly1305Parameters& XChaCha20Poly1305CrunchyParameters() {
  static const absl::NoDestructor<XChaCha20Poly1305Parameters> kParameters([] {
    absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
        XChaCha20Poly1305Parameters::Create(
            XChaCha20Poly1305Parameters::Variant::kCrunchy);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

const XChaCha20Poly1305Parameters& XChaCha20Poly1305NoPrefixParameters() {
  static const absl::NoDestructor<XChaCha20Poly1305Parameters> kParameters([] {
    absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
        XChaCha20Poly1305Parameters::Create(
            XChaCha20Poly1305Parameters::Variant::kNoPrefix);
    ABSL_CHECK_OK(parameters);
    return *parameters;
  }());
  return *kParameters;
}

struct TestVector {
  std::string name;
  const XChaCha20Poly1305Parameters& parameters;
  std::optional<int> id_requirement;
  std::string expected_prefix;
};

class XChaCha20Poly1305KeyCreatorTest : public TestWithParam<TestVector> {};

TEST_P(XChaCha20Poly1305KeyCreatorTest, CreateKey) {
  const TestVector& test_vector = GetParam();
  absl::StatusOr<std::unique_ptr<Key>> key = CreateXChaCha20Poly1305Key(
      test_vector.parameters, test_vector.id_requirement);
  ASSERT_THAT(key, IsOk());
  XChaCha20Poly1305Key* xchacha20_poly1305_key =
      dynamic_cast<XChaCha20Poly1305Key*>(key->get());
  ASSERT_NE(xchacha20_poly1305_key, nullptr);
  if (test_vector.id_requirement.has_value()) {
    EXPECT_EQ(xchacha20_poly1305_key->GetIdRequirement(),
              test_vector.id_requirement.value());
  } else {
    EXPECT_EQ(xchacha20_poly1305_key->GetIdRequirement(), std::nullopt);
  }
  EXPECT_EQ(xchacha20_poly1305_key->GetParameters(), test_vector.parameters);
  EXPECT_THAT(xchacha20_poly1305_key->GetKeyBytes(GetPartialKeyAccess())
                  .Get(InsecureSecretKeyAccess::Get()),
              SizeIs(32));

  EXPECT_EQ(xchacha20_poly1305_key->GetOutputPrefix(),
            test_vector.expected_prefix);
}

TEST(XChaCha20Poly1305KeyCreatorTest, CreateKeyFailsWithInvalidKeyId) {
  EXPECT_THAT(CreateXChaCha20Poly1305Key(XChaCha20Poly1305TinkParameters(),
                                         std::nullopt),
              Not(IsOk()));
}

INSTANTIATE_TEST_SUITE_P(
    XChaCha20Poly1305KeyCreatorTest, XChaCha20Poly1305KeyCreatorTest,
    testing::ValuesIn<TestVector>({
        {/*name=*/"XChaCha20Poly1305TinkParameters",
         /*parameters=*/XChaCha20Poly1305TinkParameters(),
         /*id_requirement=*/1,
         /*expected_prefix=*/std::string({0x01, 0x00, 0x00, 0x00, 0x01})},
        {/*name=*/"XChaCha20Poly1305CrunchyParameters",
         /*parameters=*/XChaCha20Poly1305CrunchyParameters(),
         /*id_requirement=*/2,
         /*expected_prefix=*/std::string({0x00, 0x00, 0x00, 0x00, 0x02})},
        {/*name=*/"XChaCha20Poly1305NoPrefixParameters",
         /*parameters=*/XChaCha20Poly1305NoPrefixParameters(), std::nullopt,
         /*expected_prefix=*/""},
    }),
    [](const testing::TestParamInfo<XChaCha20Poly1305KeyCreatorTest::ParamType>&
           info) { return info.param.name; });

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
