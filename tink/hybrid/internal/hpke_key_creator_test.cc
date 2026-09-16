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

#include "tink/hybrid/internal/hpke_key_creator.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Ne;

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeyWorksX25519) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkePrivateKey> key =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
}

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeyWorksP256) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkePrivateKey> key =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement().has_value(), IsFalse());
}

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeyWorksXWing) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkePrivateKey> key =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/456);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement(), Eq(456));
}

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeyWorksMlKem768) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kMlKem768)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkePrivateKey> key =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetIdRequirement().has_value(), IsFalse());
}

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/std::nullopt),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeKeyCreatorTest,
     CreatePrivateHpkeKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreatePrivateHpkeKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeKeyCreatorTest, CreatePrivateHpkeKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkePrivateKey> key1 =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<HpkePrivateKey> key2 =
      CreatePrivateHpkeKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(
      key1->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()),
      Ne(key2->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess())));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
