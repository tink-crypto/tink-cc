// Copyright 2024 Google LLC
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

#include "tink/signature/slh_dsa_parameters.h"

#include <memory>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::flat_hash_set<std::tuple<SlhDsaParameters::HashType, int,
                                     SlhDsaParameters::SignatureType>>&
GetSupportedParameterSets() {
  static const absl::NoDestructor<
      absl::flat_hash_set<std::tuple<SlhDsaParameters::HashType, int,
                                     SlhDsaParameters::SignatureType>>>
      kSupportedConfigs({// SLH-DSA-SHA2-128s
                         {SlhDsaParameters::HashType::kSha2, 64,
                          SlhDsaParameters::SignatureType::kSmallSignature},
                         // SLH-DSA-SHAKE-256f
                         {SlhDsaParameters::HashType::kShake, 128,
                          SlhDsaParameters::SignatureType::kFastSigning}});
  return *kSupportedConfigs;
}

struct VariantTestCase {
  SlhDsaParameters::Variant variant;
  bool has_id_requirement;
};

using SlhDsaParametersTest = TestWithParam<VariantTestCase>;

INSTANTIATE_TEST_SUITE_P(
    SlhDsaParametersTestSuite, SlhDsaParametersTest,
    Values(VariantTestCase{SlhDsaParameters::Variant::kTink,
                           /*has_id_requirement=*/true},
           VariantTestCase{SlhDsaParameters::Variant::kNoPrefix,
                           /*has_id_requirement=*/false}));

TEST_P(SlhDsaParametersTest, CreateSlhDsa128Sha2SmallSignatureWorks) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetHashType(), Eq(SlhDsaParameters::HashType::kSha2));
  EXPECT_THAT(parameters->GetPrivateKeySizeInBytes(), Eq(64));
  EXPECT_THAT(parameters->GetSignatureType(),
              Eq(SlhDsaParameters::SignatureType::kSmallSignature));
  EXPECT_THAT(parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(test_case.has_id_requirement));
}

TEST(SlhDsaParametersTest, CreateWithInvalidVariantFails) {
  EXPECT_THAT(
      SlhDsaParameters::Create(
          SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::
              kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SlhDsaParametersTest, CreateWithInvalidHashTypeFails) {
  EXPECT_THAT(SlhDsaParameters::Create(
                  SlhDsaParameters::HashType::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  /*private_key_size_in_bytes=*/64,
                  SlhDsaParameters::SignatureType::kSmallSignature,
                  SlhDsaParameters::Variant::kTink)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SlhDsaParametersTest, CreateWithValidCombinationsSucceeds) {
  for (const auto& config : GetSupportedParameterSets()) {
    SlhDsaParameters::HashType hash_type = std::get<0>(config);
    int private_key_size_in_bytes = std::get<1>(config);
    SlhDsaParameters::SignatureType signature_type = std::get<2>(config);

    for (auto variant : {SlhDsaParameters::Variant::kTink,
                         SlhDsaParameters::Variant::kNoPrefix}) {
      absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
          hash_type, private_key_size_in_bytes, signature_type, variant);

      ASSERT_THAT(parameters, IsOk());
      EXPECT_THAT(parameters->GetHashType(), Eq(hash_type));
      EXPECT_THAT(parameters->GetPrivateKeySizeInBytes(),
                  Eq(private_key_size_in_bytes));
      EXPECT_THAT(parameters->GetSignatureType(), Eq(signature_type));
      EXPECT_THAT(parameters->GetVariant(), Eq(variant));
      EXPECT_THAT(parameters->HasIdRequirement(),
                  Eq(variant != SlhDsaParameters::Variant::kNoPrefix));
    }
  }
}

TEST(SlhDsaParametersTest, CreateWithInvalidCombinationsFails) {
  for (auto hash_type : {SlhDsaParameters::HashType::kSha2,
                         SlhDsaParameters::HashType::kShake}) {
    for (int private_key_size_in_bytes : {64, 96, 128}) {
      for (auto signature_type :
           {SlhDsaParameters::SignatureType::kSmallSignature,
            SlhDsaParameters::SignatureType::kFastSigning}) {
        auto current_config = std::make_tuple(
            hash_type, private_key_size_in_bytes, signature_type);

        if (GetSupportedParameterSets().contains(current_config)) {
          continue;
        }

        for (auto variant : {SlhDsaParameters::Variant::kTink,
                             SlhDsaParameters::Variant::kNoPrefix}) {
          EXPECT_THAT(
              SlhDsaParameters::Create(hash_type, private_key_size_in_bytes,
                                       signature_type, variant)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
        }
      }
    }
  }
}

TEST(SlhDsaParametersTest, CreateWithInvalidSignatureTypeFails) {
  EXPECT_THAT(SlhDsaParameters::Create(
                  SlhDsaParameters::HashType::kSha2,
                  /*private_key_size_in_bytes=*/64,
                  SlhDsaParameters::SignatureType::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements,
                  SlhDsaParameters::Variant::kTink)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SlhDsaParametersTest, CreateWithInvalidKeySizeFails) {
  EXPECT_THAT(
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/31,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(SlhDsaParametersTest, CopyConstructor) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  SlhDsaParameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(SlhDsaParametersTest, CopyAssignment) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaParameters> copy =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(SlhDsaParametersTest, MoveConstructor) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  SlhDsaParameters expected(*parameters);
  SlhDsaParameters moved(std::move(*parameters));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(SlhDsaParametersTest, MoveAssignment) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaParameters> moved =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(moved, IsOk());

  SlhDsaParameters expected(*parameters);
  *moved = std::move(*parameters);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST_P(SlhDsaParametersTest, ParametersEquals) {
  VariantTestCase test_case = GetParam();

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaParameters> other_parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(SlhDsaParametersTest, DifferentVariantNotEqual) {
  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);

  absl::StatusOr<SlhDsaParameters> other_parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(SlhDsaParametersTest, Clone) {
  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  EXPECT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
