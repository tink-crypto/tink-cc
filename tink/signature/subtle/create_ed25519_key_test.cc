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

#include "tink/signature/subtle/create_ed25519_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Ne;

TEST(CreateEd25519KeyTest, CreateEd25519PrivateKeyWorks) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Ed25519PrivateKey> private_key =
      CreateEd25519PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateEd25519KeyTest, CreateEd25519PrivateKeyWithoutIdRequirement) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Ed25519PrivateKey> private_key =
      CreateEd25519PrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateEd25519KeyTest,
     CreateEd25519PrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateEd25519PrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateEd25519KeyTest,
     CreateEd25519PrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateEd25519PrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateEd25519KeyTest, CreateEd25519PrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<Ed25519PrivateKey> key1 =
      CreateEd25519PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<Ed25519PrivateKey> key2 =
      CreateEd25519PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(
      key1->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()),
      Ne(key2->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
