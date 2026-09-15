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

#include "tink/hybrid/subtle/create_ecies_key.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;

TEST(EciesKeyTest, CreateEciesPrivateKeyWorks) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key =
      CreateEciesPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
}

TEST(EciesKeyTest, CreateEciesPrivateKeyWithoutIdRequirementWorks) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      CreateEciesPrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), testing::IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(EciesKeyTest, CreateEciesPrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateEciesPrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesKeyTest, CreateEciesPrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateEciesPrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesKeyTest, CreateEciesPrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key1 =
      CreateEciesPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<EciesPrivateKey> key2 =
      CreateEciesPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  // Distinctness test
  EXPECT_NE(
      key1->GetPublicKey().GetNistCurvePoint(GetPartialKeyAccess())->GetX(),
      key2->GetPublicKey().GetNistCurvePoint(GetPartialKeyAccess())->GetX());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
