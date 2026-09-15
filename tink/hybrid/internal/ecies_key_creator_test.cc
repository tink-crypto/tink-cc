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

#include "tink/hybrid/internal/ecies_key_creator.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;

TEST(EciesKeyCreatorTest, CreateEciesKeyWorksNistP256) {
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
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_EQ(key->GetParameters(), *parameters);
  EXPECT_EQ(key->GetIdRequirement(), 123);
}

TEST(EciesKeyCreatorTest, CreateEciesKeyWorksX25519) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key =
      CreateEciesKey(*parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_EQ(key->GetParameters(), *parameters);
  EXPECT_FALSE(key->GetIdRequirement().has_value());
}

TEST(EciesKeyCreatorTest, CreateEciesKeyWorksNistP384) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP384)
          .SetHashType(EciesParameters::HashType::kSha384)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key =
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_EQ(key->GetParameters(), *parameters);
  EXPECT_EQ(key->GetIdRequirement(), 123);
}

TEST(EciesKeyCreatorTest, CreateEciesKeyWorksNistP521) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP521)
          .SetHashType(EciesParameters::HashType::kSha512)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key =
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_EQ(key->GetParameters(), *parameters);
  EXPECT_EQ(key->GetIdRequirement(), 123);
}

TEST(EciesKeyCreatorTest, CreateEciesKeyFailsWithMissingIdRequirement) {
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
      CreateEciesKey(*parameters, /*id_requirement=*/std::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesKeyCreatorTest, CreateEciesKeyFailsWithUnexpectedIdRequirement) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key =
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesKeyCreatorTest, CreateEciesKeyGeneratesDistinctKeys) {
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
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<EciesPrivateKey> key2 =
      CreateEciesKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(key1->GetNistPrivateKeyBytes(GetPartialKeyAccess())
                ->GetSecret(InsecureSecretKeyAccess::Get()),
            key2->GetNistPrivateKeyBytes(GetPartialKeyAccess())
                ->GetSecret(InsecureSecretKeyAccess::Get()));
}

TEST(EciesKeyCreatorTest, CreateEciesKeyGeneratesDistinctKeysX25519) {
  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EciesPrivateKey> key1 =
      CreateEciesKey(*parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<EciesPrivateKey> key2 =
      CreateEciesKey(*parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(key1->GetX25519PrivateKeyBytes(GetPartialKeyAccess())
                ->GetSecret(InsecureSecretKeyAccess::Get()),
            key2->GetX25519PrivateKeyBytes(GetPartialKeyAccess())
                ->GetSecret(InsecureSecretKeyAccess::Get()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
