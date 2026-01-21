// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_parameters.h"

#include <memory>
#include <tuple>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/parameters.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Combine;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::TestWithParam;
using ::testing::Values;

struct VariantWithIdRequirement {
  HpkeParameters::Variant variant;
  bool has_id_requirement;
};

using HpkeParametersTest =
    TestWithParam<std::tuple<HpkeParameters::KemId, HpkeParameters::KdfId,
                             HpkeParameters::AeadId, VariantWithIdRequirement>>;

INSTANTIATE_TEST_SUITE_P(
    HpkeParametersTestSuite, HpkeParametersTest,
    Combine(Values(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                   HpkeParameters::KemId::kDhkemP384HkdfSha384,
                   HpkeParameters::KemId::kDhkemP521HkdfSha512,
                   HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                   HpkeParameters::KemId::kXWing,
                   HpkeParameters::KemId::kMlKem768,
                   HpkeParameters::KemId::kMlKem1024),
            Values(HpkeParameters::KdfId::kHkdfSha256,
                   HpkeParameters::KdfId::kHkdfSha384,
                   HpkeParameters::KdfId::kHkdfSha512),
            Values(HpkeParameters::AeadId::kAesGcm128,
                   HpkeParameters::AeadId::kAesGcm256,
                   HpkeParameters::AeadId::kChaCha20Poly1305),
            Values(VariantWithIdRequirement{HpkeParameters::Variant::kTink,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{HpkeParameters::Variant::kCrunchy,
                                            /*has_id_requirement=*/true},
                   VariantWithIdRequirement{HpkeParameters::Variant::kNoPrefix,
                                            /*has_id_requirement=*/false})));

TEST_P(HpkeParametersTest, Build) {
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  VariantWithIdRequirement variant;
  std::tie(kem_id, kdf_id, aead_id, variant) = GetParam();

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(variant.variant)
                                                  .SetKemId(kem_id)
                                                  .SetKdfId(kdf_id)
                                                  .SetAeadId(aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetKemId(), Eq(kem_id));
  EXPECT_THAT(parameters->GetKdfId(), Eq(kdf_id));
  EXPECT_THAT(parameters->GetAeadId(), Eq(aead_id));
  EXPECT_THAT(parameters->GetVariant(), Eq(variant.variant));
  EXPECT_THAT(parameters->HasIdRequirement(), Eq(variant.has_id_requirement));
}

TEST(HpkeParametersTest, BuildWithInvalidVariantFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::
                          kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutVariantFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidKemIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::
                        kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutKemIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidKdfIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::
                        kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutKdfIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithInvalidAeadIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::
                         kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements)
          .Build();
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, BuildWithoutAeadIdFails) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .Build();

  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkeParametersTest, CopyConstructor) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  HpkeParameters copy(*parameters);

  EXPECT_THAT(copy, Eq(*parameters));
}

TEST(HpkeParametersTest, CopyAssignment) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> copy =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(copy, IsOk());

  *copy = *parameters;

  EXPECT_THAT(*copy, Eq(*parameters));
}

TEST(HpkeParametersTest, MoveConstructor) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  HpkeParameters expected = *parameters;
  HpkeParameters moved(std::move(*parameters));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HpkeParametersTest, MoveAssignment) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> moved =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(moved, IsOk());

  HpkeParameters expected = *parameters;
  *moved = std::move(*parameters);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST_P(HpkeParametersTest, ParametersEquals) {
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  VariantWithIdRequirement variant;
  std::tie(kem_id, kdf_id, aead_id, variant) = GetParam();

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(variant.variant)
                                                  .SetKemId(kem_id)
                                                  .SetKdfId(kdf_id)
                                                  .SetAeadId(aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(variant.variant)
          .SetKemId(kem_id)
          .SetKdfId(kdf_id)
          .SetAeadId(aead_id)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(HpkeParametersTest, VariantNotEqual) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, KemIdNotEqual) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, KdfIdNotEqual) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, AeadIdNotEqual) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<HpkeParameters> other_parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(HpkeParametersTest, Clone) {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> cloned_parameters = parameters->Clone();
  ASSERT_THAT(*cloned_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
