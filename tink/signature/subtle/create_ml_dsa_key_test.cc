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

#include "tink/signature/subtle/create_ml_dsa_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Ne;

TEST(CreateMlDsaKeyTest, CreateMlDsaPrivateKeyWorks) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key =
      CreateMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateMlDsaKeyTest, CreateMlDsaPrivateKeyWithoutIdRequirement) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa44, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key =
      CreateMlDsaPrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateMlDsaKeyTest,
     CreateMlDsaPrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateMlDsaPrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateMlDsaKeyTest,
     CreateMlDsaPrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateMlDsaPrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateMlDsaKeyTest, CreateMlDsaPrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPrivateKey> key1 =
      CreateMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<MlDsaPrivateKey> key2 =
      CreateMlDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(
      key1->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()),
      Ne(key2->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
