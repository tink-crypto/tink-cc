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

#include "tink/aead/x_aes_gcm_key.h"

#include <memory>
#include <optional>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/x_aes_gcm_test_vectors.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr int kSaltSizeBytes = 12;

using XAesGcmKeyTest = TestWithParam<internal::AeadTestVector>;

INSTANTIATE_TEST_SUITE_P(XAesGcmKeyTestSuite, XAesGcmKeyTest,
                         ValuesIn(internal::CreateXAesGcmTestVectors()));

TEST_P(XAesGcmKeyTest, CreateSucceeds) {
  const internal::AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);

  absl::StatusOr<XAesGcmKey> created_key = XAesGcmKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  EXPECT_THAT(created_key->GetKeyBytes(GetPartialKeyAccess()),
              Eq(key.GetKeyBytes(GetPartialKeyAccess())));
  EXPECT_THAT(created_key->GetParameters(), Eq(key.GetParameters()));
  EXPECT_THAT(created_key->GetIdRequirement(), Eq(key.GetIdRequirement()));
  EXPECT_THAT(created_key->GetOutputPrefix(), Eq(key.GetOutputPrefix()));
}

TEST(XAesGcmKeyTest, CreateKeyWithInvalidKeySizeFails) {
  // Key material must be 32 bytes.
  RestrictedData invalid_secret = RestrictedData(/*num_random_bytes=*/16);

  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(XAesGcmKey::Create(*params, invalid_secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(XAesGcmKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  RestrictedData secret = dynamic_cast<const XAesGcmKey&>(
                              *internal::GetXAesGcmTestVector(
                                   12, XAesGcmParameters::Variant::kNoPrefix)
                                   .aead_key)
                              .GetKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(XAesGcmKey::Create(*params, secret,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  absl::StatusOr<XAesGcmParameters> other_params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(other_params, IsOk());

  EXPECT_THAT(
      XAesGcmKey::Create(*other_params, secret,
                         /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(XAesGcmKeyTest, KeyEquals) {
  const internal::AeadTestVector& test_vector = GetParam();
  const XAesGcmKey& key =
      dynamic_cast<const XAesGcmKey&>(*test_vector.aead_key);

  absl::StatusOr<XAesGcmKey> created_key = XAesGcmKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(created_key, IsOk());

  absl::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      key.GetParameters(), key.GetKeyBytes(GetPartialKeyAccess()),
      key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*created_key == *other_key);
  EXPECT_TRUE(*other_key == *created_key);
  EXPECT_FALSE(*created_key != *other_key);
  EXPECT_FALSE(*other_key != *created_key);
}

TEST(XAesGcmKeyTest, DifferentVariantNotEqual) {
  const XAesGcmKey& tink_key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);
  const XAesGcmKey& no_prefix_key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kNoPrefix)
           .aead_key);

  EXPECT_TRUE(tink_key != no_prefix_key);
  EXPECT_TRUE(no_prefix_key != tink_key);
  EXPECT_FALSE(tink_key == no_prefix_key);
  EXPECT_FALSE(no_prefix_key == tink_key);
}

TEST(XAesGcmKeyTest, DifferentSecretDataNotEqual) {
  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret1 =
      dynamic_cast<const XAesGcmKey&>(
          *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
               .aead_key)
          .GetKeyBytes(GetPartialKeyAccess());
  RestrictedData secret2 = RestrictedData(/*num_random_bytes=*/32);

  absl::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret1, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *params, secret2, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<XAesGcmParameters> params = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kTink, kSaltSizeBytes);
  ASSERT_THAT(params, IsOk());

  RestrictedData secret =
      dynamic_cast<const XAesGcmKey&>(
          *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
               .aead_key)
          .GetKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *params, secret, /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<XAesGcmKey> other_key = XAesGcmKey::Create(
      *params, secret, /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(XAesGcmKeyTest, DifferentSaltSizeNotEqual) {
  const XAesGcmKey& key12 = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);
  const XAesGcmKey& key8 = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(8, XAesGcmParameters::Variant::kTink)
           .aead_key);

  EXPECT_TRUE(key12 != key8);
  EXPECT_TRUE(key8 != key12);
  EXPECT_FALSE(key12 == key8);
  EXPECT_FALSE(key8 == key12);
}

TEST(XAesGcmKeyTest, CopyConstructor) {
  const XAesGcmKey& key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);

  XAesGcmKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(XAesGcmKeyTest, CopyAssignment) {
  const XAesGcmKey& key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);
  const XAesGcmKey& other_key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(8, XAesGcmParameters::Variant::kNoPrefix)
           .aead_key);

  XAesGcmKey copy = other_key;
  copy = key;

  EXPECT_THAT(copy, Eq(key));
}

TEST(XAesGcmKeyTest, MoveConstructor) {
  XAesGcmKey key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);

  XAesGcmKey expected = key;
  XAesGcmKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(XAesGcmKeyTest, MoveAssignment) {
  XAesGcmKey key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);
  XAesGcmKey other_key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(8, XAesGcmParameters::Variant::kNoPrefix)
           .aead_key);

  XAesGcmKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}

TEST(XAesGcmKeyTest, Clone) {
  const XAesGcmKey& key = dynamic_cast<const XAesGcmKey&>(
      *internal::GetXAesGcmTestVector(12, XAesGcmParameters::Variant::kTink)
           .aead_key);

  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
