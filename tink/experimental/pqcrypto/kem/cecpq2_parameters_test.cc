// Copyright 2025 Google LLC
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

#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

std::shared_ptr<Parameters> CreateAesGcmParams() {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return absl::make_unique<AesGcmParameters>(*parameters);
}

std::shared_ptr<Parameters> CreateXChaCha20Poly1305Params() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return absl::make_unique<XChaCha20Poly1305Parameters>(*parameters);
}

std::shared_ptr<Parameters> CreateAesSivParams() {
  absl::StatusOr<AesSivParameters> parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/32, AesSivParameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return absl::make_unique<AesSivParameters>(*parameters);
}

struct TestCase {
  std::shared_ptr<Parameters> dem_parameters;
  absl::optional<absl::string_view> salt;
  Cecpq2Parameters::Variant variant;
};

using Cecpq2ParametersTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(Cecpq2ParametersTests, Cecpq2ParametersTest,
                         Values(TestCase{CreateAesGcmParams(), "salt1",
                                         Cecpq2Parameters::Variant::kTink},
                                TestCase{CreateXChaCha20Poly1305Params(),
                                         /*salt=*/absl::nullopt,
                                         Cecpq2Parameters::Variant::kNoPrefix},
                                TestCase{CreateAesSivParams(), "salt3",
                                         Cecpq2Parameters::Variant::kTink}));

TEST_P(Cecpq2ParametersTest, Create) {
  TestCase test_case = GetParam();

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *test_case.dem_parameters, test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_TRUE(parameters->GetDemParameters() == *test_case.dem_parameters);
  EXPECT_THAT(parameters->GetSalt(), Eq(test_case.salt));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
}

TEST(Cecpq2ParametersTest, CreateWithInvalidDemParameters) {
  absl::StatusOr<ChaCha20Poly1305Parameters> dem_parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);

  EXPECT_THAT(parameters, StatusIs(absl::StatusCode::kInvalidArgument,
                                   HasSubstr("DEM parameters must be")));
}

TEST(Cecpq2ParametersTest, CreateWithInvalidVariant) {
  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *CreateXChaCha20Poly1305Params(), "salt",
      Cecpq2Parameters::Variant::
          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements);

  EXPECT_THAT(
      parameters,
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Cannot create CECPQ2 parameters with unknown variant")));
}

TEST(Cecpq2ParametersTest, CreateWithInvalidDemVariant) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);

  EXPECT_THAT(parameters,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("DEM requires no-prefix variant")));
}

TEST_P(Cecpq2ParametersTest, ParametersEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *test_case.dem_parameters, test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> other_parameters = Cecpq2Parameters::Create(
      *test_case.dem_parameters, test_case.salt, test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(Cecpq2ParametersTest, DemParametersNotEqual) {
  absl::StatusOr<AesSivParameters> dem_parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/32, AesSivParameters::Variant::kNoPrefix);

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<AesSivParameters> other_dem_parameters =
      AesSivParameters::Create(
          /*key_size_in_bytes=*/64, AesSivParameters::Variant::kNoPrefix);

  absl::StatusOr<Cecpq2Parameters> other_parameters = Cecpq2Parameters::Create(
      *other_dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_TRUE(*other_parameters != *parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
  EXPECT_FALSE(*other_parameters == *parameters);
}

TEST(Cecpq2ParametersTest, SaltNotEqual) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt1",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> other_parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt2",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_TRUE(*other_parameters != *parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
  EXPECT_FALSE(*other_parameters == *parameters);
}

TEST(Cecpq2ParametersTest, VariantNotEqual) {
  absl::StatusOr<AesSivParameters> dem_parameters = AesSivParameters::Create(
      /*key_size_in_bytes=*/32, AesSivParameters::Variant::kNoPrefix);

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> other_parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_TRUE(*other_parameters != *parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
  EXPECT_FALSE(*other_parameters == *parameters);
}

TEST(Cecpq2ParametersTest, CopyConstructor) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  Cecpq2Parameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(Cecpq2ParametersTest, CopyAssignment) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> copy =
      Cecpq2Parameters::Create(*CreateAesGcmParams(),
                               /*salt=*/"", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(Cecpq2ParametersTest, MoveConstructor) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  Cecpq2Parameters move(std::move(*parameters));

  EXPECT_TRUE(move.GetDemParameters() == *CreateXChaCha20Poly1305Params());
  EXPECT_THAT(move.GetSalt(), Eq("salt"));
  EXPECT_THAT(move.GetVariant(), Cecpq2Parameters::Variant::kNoPrefix);
}

TEST(Cecpq2ParametersTest, MoveAssignment) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> move =
      Cecpq2Parameters::Create(*CreateAesGcmParams(),
                               /*salt=*/"", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(move, IsOk());

  *move = std::move(*parameters);

  EXPECT_TRUE(move->GetDemParameters() == *CreateXChaCha20Poly1305Params());
  EXPECT_THAT(move->GetSalt(), Eq("salt"));
  EXPECT_THAT(move->GetVariant(), Cecpq2Parameters::Variant::kNoPrefix);
}

TEST(Cecpq2ParametersTest, Clone) {
  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> clone = parameters->Clone();

  EXPECT_THAT(*clone, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
