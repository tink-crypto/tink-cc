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

#include "tink/signature/subtle/create_composite_ml_dsa_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;

TEST(CreateCompositeMlDsaKeyTest, CreateCompositeMlDsaPrivateKeyWorks) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CreateCompositeMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateCompositeMlDsaKeyTest,
     CreateCompositeMlDsaPrivateKeyWithoutIdRequirement) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> private_key =
      CreateCompositeMlDsaPrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateCompositeMlDsaKeyTest,
     CreateCompositeMlDsaPrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateCompositeMlDsaPrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateCompositeMlDsaKeyTest,
     CreateCompositeMlDsaPrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(
      CreateCompositeMlDsaPrivateKey(*parameters, /*id_requirement=*/123),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateCompositeMlDsaKeyTest,
     CreateCompositeMlDsaPrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> key1 =
      CreateCompositeMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<CompositeMlDsaPrivateKey> key2 =
      CreateCompositeMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(key1->GetMlDsaPrivateKey(), key2->GetMlDsaPrivateKey());
  EXPECT_NE(key1->GetClassicalPrivateKey(), key2->GetClassicalPrivateKey());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
