// Copyright 2023 Google LLC
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

#include "tink/hybrid/hpke_private_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/internal/secret_buffer.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateHpkeMlKemTestCases;
using ::crypto::tink::internal::CreateHpkeNistCurveTestCases;
using ::crypto::tink::internal::GetHpkeMlKemKeyPairBytes;
using ::crypto::tink::internal::GetHpkeNistCurveKeyPairBytes;
using ::crypto::tink::internal::GetHpkeTestVector;
using ::crypto::tink::internal::HpkeKeyPairBytes;
using ::crypto::tink::internal::HpkeMlKemTestCase;
using ::crypto::tink::internal::HpkeNistCurveTestCase;
using ::crypto::tink::internal::X25519PublicValue;
using ::crypto::tink::internal::X25519SecretValue;
using ::crypto::tink::internal::XWingPublicValue;
using ::crypto::tink::internal::XWingSecretValue;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using HpkePrivateKeyTest = TestWithParam<HpkeNistCurveTestCase>;

INSTANTIATE_TEST_SUITE_P(HpkePrivateKeyTestSuite, HpkePrivateKeyTest,
                         ValuesIn(CreateHpkeNistCurveTestCases()));

using HpkeMlKemPrivateKeyTest = TestWithParam<HpkeMlKemTestCase>;

INSTANTIATE_TEST_SUITE_P(HpkeMlKemPrivateKeyTestSuite, HpkeMlKemPrivateKeyTest,
                         ValuesIn(CreateHpkeMlKemTestCases()));

TEST_P(HpkePrivateKeyTest, CreateNistCurvePrivateKey) {
  HpkeNistCurveTestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<HpkeKeyPairBytes> key_pair_bytes =
      GetHpkeNistCurveKeyPairBytes(test_case.curve);
  ASSERT_THAT(key_pair_bytes, IsOk());

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, key_pair_bytes->public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, key_pair_bytes->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(key_pair_bytes->private_key_bytes));
}

TEST(HpkePrivateKeyTest, CreateX25519PrivateKey) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = X25519PublicValue();
  RestrictedData private_key_bytes = X25519SecretValue();

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST(HpkePrivateKeyTest, CreateXWingPrivateKey) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = XWingPublicValue();
  RestrictedData private_key_bytes = XWingSecretValue();

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST_P(HpkeMlKemPrivateKeyTest, CreateMlKemPrivateKey) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(GetParam().kem_id)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  HpkeKeyPairBytes key_pair_bytes =
      GetHpkeMlKemKeyPairBytes(GetParam().key_size);

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, key_pair_bytes.public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, key_pair_bytes.private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(key_pair_bytes.private_key_bytes));
}

TEST_P(HpkePrivateKeyTest, CreateMismatchedNistCurveKeyPairFails) {
  HpkeNistCurveTestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  auto key_pair_bytes = GetHpkeNistCurveKeyPairBytes(test_case.curve);
  ASSERT_THAT(key_pair_bytes, IsOk());

  absl::StatusOr<HpkePublicKey> public_key1 =
      HpkePublicKey::Create(*params, key_pair_bytes->public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  // Tweak the private key to make it mismatch.
  std::string mismatched_private_key_bytes(
      key_pair_bytes->private_key_bytes.GetSecret(
          InsecureSecretKeyAccess::Get()));
  mismatched_private_key_bytes[15] ^= 1;
  RestrictedData mismatched_private_key(mismatched_private_key_bytes,
                                        InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key1, mismatched_private_key,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyTest, CreateMismatchedX25519KeyPairFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = X25519PublicValue();
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string mismatched_private_key_bytes(
      X25519SecretValue().GetSecret(InsecureSecretKeyAccess::Get()));
  mismatched_private_key_bytes[15] ^= 1;
  RestrictedData private_key_bytes = RestrictedData(
      mismatched_private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyTest, CreateMismatchedXWingKeyPairFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = XWingPublicValue();
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string mismatched_private_key_bytes(
      XWingSecretValue().GetSecret(InsecureSecretKeyAccess::Get()));
  mismatched_private_key_bytes[15] ^= 1;
  RestrictedData private_key_bytes = RestrictedData(
      mismatched_private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeMlKemPrivateKeyTest, CreateMismatchedMlKemKeyPairFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(GetParam().kem_id)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  HpkeKeyPairBytes key_pair_bytes =
      GetHpkeMlKemKeyPairBytes(GetParam().key_size);

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, key_pair_bytes.public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::string mismatched_private_key_bytes(
      key_pair_bytes.private_key_bytes.GetSecret(
          InsecureSecretKeyAccess::Get()));
  mismatched_private_key_bytes[15] ^= 1;
  RestrictedData private_key_bytes = RestrictedData(
      mismatched_private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePrivateKeyTest, CreateNistPrivateKeyWithInvalidKeyLengthFails) {
  HpkeNistCurveTestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  auto key_pair_bytes = GetHpkeNistCurveKeyPairBytes(test_case.curve);
  ASSERT_THAT(key_pair_bytes, IsOk());

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, key_pair_bytes->public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  internal::SecretBuffer private_key_input = util::internal::AsSecretBuffer(
      key_pair_bytes->private_key_bytes.Get(InsecureSecretKeyAccess::Get()));
  private_key_input.resize(private_key_input.size() + 1);
  RestrictedData expanded_private_key_bytes(
      util::internal::AsSecretData(std::move(private_key_input)),
      InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, expanded_private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyTest, CreateX25519PrivateKeyWithInvalidKeyLengthFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = X25519PublicValue();
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(
          test::HexDecodeOrDie("00"),
          X25519SecretValue().GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, expanded_private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyTest, CreateXWingPrivateKeyWithInvalidKeyLengthFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = XWingPublicValue();
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(
          test::HexDecodeOrDie("00"),
          XWingSecretValue().GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, expanded_private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeMlKemPrivateKeyTest,
       CreateMlKemPrivateKeyWithInvalidKeyLengthFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(GetParam().kem_id)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  HpkeKeyPairBytes key_pair_bytes =
      GetHpkeMlKemKeyPairBytes(GetParam().key_size);

  RestrictedData expanded_private_key_bytes =
      RestrictedData(absl::StrCat(test::HexDecodeOrDie("00"),
                                  key_pair_bytes.private_key_bytes.GetSecret(
                                      InsecureSecretKeyAccess::Get())),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, key_pair_bytes.public_key_bytes, /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, expanded_private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePrivateKeyTest, NistCurvePrivateKeyEquals) {
  const HpkePrivateKey& private_key = *GetParam().private_key;
  HpkePrivateKey other_private_key = private_key;

  EXPECT_TRUE(private_key == other_private_key);
  EXPECT_TRUE(other_private_key == private_key);
  EXPECT_FALSE(private_key != other_private_key);
  EXPECT_FALSE(other_private_key != private_key);
}

TEST(HpkePrivateKeyTest, X25519PrivateKeyEquals) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  HpkePrivateKey other_private_key = private_key;

  EXPECT_TRUE(private_key == other_private_key);
  EXPECT_TRUE(other_private_key == private_key);
  EXPECT_FALSE(private_key != other_private_key);
  EXPECT_FALSE(other_private_key != private_key);
}

TEST(HpkePrivateKeyTest, XWingPrivateKeyEquals) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kXWing,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  HpkePrivateKey other_private_key = private_key;

  EXPECT_TRUE(private_key == other_private_key);
  EXPECT_TRUE(other_private_key == private_key);
  EXPECT_FALSE(private_key != other_private_key);
  EXPECT_FALSE(other_private_key != private_key);
}

TEST_P(HpkeMlKemPrivateKeyTest, MlKemPrivateKeyEquals) {
  const HpkePrivateKey& private_key = *GetParam().private_key;
  HpkePrivateKey other_private_key = private_key;

  EXPECT_TRUE(private_key == other_private_key);
  EXPECT_TRUE(other_private_key == private_key);
  EXPECT_FALSE(private_key != other_private_key);
  EXPECT_FALSE(other_private_key != private_key);
}

TEST(HpkePrivateKeyTest, DifferentPublicKeyNotEqual) {
  const auto& key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kTink)
           .hybrid_private_key);
  const auto& key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(HpkePrivateKeyTest, DifferentKeyTypesNotEqual) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& public_key = private_key.GetPublicKey();

  EXPECT_TRUE(private_key != public_key);
  EXPECT_TRUE(public_key != private_key);
  EXPECT_FALSE(private_key == public_key);
  EXPECT_FALSE(public_key == private_key);
}

TEST(HpkePrivateKeyTest, CopyConstructor) {
  const auto& key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);

  HpkePrivateKey copy(key);

  EXPECT_THAT(copy, Eq(key));
}

TEST(HpkePrivateKeyTest, CopyAssignment) {
  const auto& key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const auto& key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);

  HpkePrivateKey copy = key2;
  copy = key1;

  EXPECT_THAT(copy, Eq(key1));
}

TEST(HpkePrivateKeyTest, MoveConstructor) {
  HpkePrivateKey key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);

  HpkePrivateKey expected = key;
  HpkePrivateKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HpkePrivateKeyTest, MoveAssignment) {
  HpkePrivateKey key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  HpkePrivateKey key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);

  HpkePrivateKey expected = key1;
  key2 = std::move(key1);

  EXPECT_THAT(key2, Eq(expected));
}

TEST(HpkePrivateKeyTest, Clone) {
  const auto& key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
