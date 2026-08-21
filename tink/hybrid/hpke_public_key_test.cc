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

#include "tink/hybrid/hpke_public_key.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
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
using ::crypto::tink::internal::HpkeMlKemTestCase;
using ::crypto::tink::internal::HpkeNistCurveTestCase;
using ::crypto::tink::internal::P256PointAsString;
using ::crypto::tink::internal::X25519PublicValue;
using ::crypto::tink::internal::XWingPublicValue;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using HpkePublicKeyTest = TestWithParam<HpkeNistCurveTestCase>;

INSTANTIATE_TEST_SUITE_P(HpkePublicKeyTestSuite, HpkePublicKeyTest,
                         ValuesIn(CreateHpkeNistCurveTestCases()));

using HpkeMlKemPublicKeyTest = TestWithParam<HpkeMlKemTestCase>;

INSTANTIATE_TEST_SUITE_P(HpkeMlKemPublicKeyTestSuite, HpkeMlKemPublicKeyTest,
                         ValuesIn(CreateHpkeMlKemTestCases()));

TEST_P(HpkePublicKeyTest, CreateNistCurvePublicKey) {
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

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(key_pair_bytes->public_key_bytes));
}

TEST(HpkePublicKeyTest, CreateX25519PublicKey) {
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

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST(HpkePublicKeyTest, CreateXWingPublicKey) {
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

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST_P(HpkeMlKemPublicKeyTest, CreateMlKemPublicKey) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(GetParam().kem_id)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      GetHpkeMlKemKeyPairBytes(GetParam().key_size).public_key_bytes;

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST_P(HpkePublicKeyTest, CreateNistCurvePublicKeyWithInvalidLength) {
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

  std::string public_key_bytes = key_pair_bytes->public_key_bytes;
  public_key_bytes.resize(public_key_bytes.size() - 1);

  EXPECT_THAT(
      HpkePublicKey::Create(*params, public_key_bytes, test_case.id_requirement,
                            GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePublicKeyTest, CreateX25519PublicKeyWithInvalidLength) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = X25519PublicValue();
  public_key_bytes.resize(public_key_bytes.size() - 1);

  EXPECT_THAT(HpkePublicKey::Create(*params, public_key_bytes,
                                    /*id_requirement=*/std::nullopt,
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePublicKeyTest, CreateXWingPublicKeyWithInvalidLength) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = XWingPublicValue();
  public_key_bytes.resize(public_key_bytes.size() - 1);

  EXPECT_THAT(HpkePublicKey::Create(*params, public_key_bytes,
                                    /*id_requirement=*/std::nullopt,
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeMlKemPublicKeyTest, CreateMlKemPublicKeyWithInvalidLength) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(GetParam().kem_id)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes =
      GetHpkeMlKemKeyPairBytes(GetParam().key_size).public_key_bytes;
  public_key_bytes.resize(public_key_bytes.size() - 1);

  EXPECT_THAT(HpkePublicKey::Create(*params, public_key_bytes,
                                    /*id_requirement=*/std::nullopt,
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePublicKeyTest, CreateNistCurvePublicKeyWithInvalidPoint) {
  // Copied from "public point not on curve" Wycheproof test case in
  // https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256k1_test.json.
  std::string invalid_point = test::HexDecodeOrDie(
      "3056301006072a8648ce3d020106052b8104000a0342000449c248edc659e18482b71057"
      "48a4b95d3a46952a5ba72da0d702dc97a64e99799d8cff7a5c4b925e4360ece25ccf307d"
      "7a9a7063286bbd16ef64c65f546757e4");

  absl::StatusOr<int32_t> point_size =
      internal::EcPointEncodingSizeInBytes(subtle::EllipticCurveType::NIST_P256,
                                           subtle::EcPointFormat::UNCOMPRESSED);
  ASSERT_THAT(point_size, IsOk());
  ASSERT_THAT(*point_size, testing::Lt(invalid_point.size()));

  std::string public_key_bytes =
      invalid_point.substr(invalid_point.size() - *point_size, *point_size);
  // Uncompressed point format starts with a 0x04-byte.
  ASSERT_THAT(public_key_bytes[0], Eq(0x04));

  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(HpkePublicKeyTest, CreatePublicKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<HpkeParameters> no_prefix_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  std::string public_key_bytes = P256PointAsString();

  EXPECT_THAT(
      HpkePublicKey::Create(*no_prefix_params, public_key_bytes,
                            /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  absl::StatusOr<HpkeParameters> tink_params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  EXPECT_THAT(HpkePublicKey::Create(*tink_params, public_key_bytes,
                                    /*id_requirement=*/std::nullopt,
                                    GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePublicKeyTest, NistCurvePublicKeyEquals) {
  const HpkePublicKey& public_key = GetParam().private_key->GetPublicKey();
  HpkePublicKey other_public_key = public_key;

  EXPECT_TRUE(public_key == other_public_key);
  EXPECT_TRUE(other_public_key == public_key);
  EXPECT_FALSE(public_key != other_public_key);
  EXPECT_FALSE(other_public_key != public_key);
}

TEST(HpkePublicKeyTest, X25519PublicKeyEquals) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& public_key = private_key.GetPublicKey();
  HpkePublicKey other_public_key = public_key;

  EXPECT_TRUE(public_key == other_public_key);
  EXPECT_TRUE(other_public_key == public_key);
  EXPECT_FALSE(public_key != other_public_key);
  EXPECT_FALSE(other_public_key != public_key);
}

TEST(HpkePublicKeyTest, XWingPublicKeyEquals) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kXWing,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& public_key = private_key.GetPublicKey();
  HpkePublicKey other_public_key = public_key;

  EXPECT_TRUE(public_key == other_public_key);
  EXPECT_TRUE(other_public_key == public_key);
  EXPECT_FALSE(public_key != other_public_key);
  EXPECT_FALSE(other_public_key != public_key);
}

TEST_P(HpkeMlKemPublicKeyTest, MlKemPublicKeyEquals) {
  const HpkePublicKey& public_key = GetParam().private_key->GetPublicKey();
  HpkePublicKey other_public_key = public_key;

  EXPECT_TRUE(public_key == other_public_key);
  EXPECT_TRUE(other_public_key == public_key);
  EXPECT_FALSE(public_key != other_public_key);
  EXPECT_FALSE(other_public_key != public_key);
}

TEST(HpkePublicKeyTest, DifferentVariantNotEqual) {
  const auto& private_key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kTink)
           .hybrid_private_key);
  const auto& private_key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);
  const HpkePublicKey& public_key1 = private_key1.GetPublicKey();
  const HpkePublicKey& public_key2 = private_key2.GetPublicKey();

  EXPECT_TRUE(public_key1 != public_key2);
  EXPECT_TRUE(public_key2 != public_key1);
  EXPECT_FALSE(public_key1 == public_key2);
  EXPECT_FALSE(public_key2 == public_key1);
}

TEST(HpkePublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& public_key1 = private_key.GetPublicKey();

  std::string public_key_bytes2 = X25519PublicValue();
  public_key_bytes2[0] ^= 1;

  absl::StatusOr<HpkePublicKey> public_key2 = HpkePublicKey::Create(
      public_key1.GetParameters(), public_key_bytes2,
      public_key1.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  EXPECT_TRUE(public_key1 != *public_key2);
  EXPECT_TRUE(*public_key2 != public_key1);
  EXPECT_FALSE(public_key1 == *public_key2);
  EXPECT_FALSE(*public_key2 == public_key1);
}

TEST(HpkePublicKeyTest, DifferentIdRequirementNotEqual) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kTink)
           .hybrid_private_key);
  const HpkePublicKey& public_key1 = private_key.GetPublicKey();

  absl::StatusOr<HpkePublicKey> public_key2 = HpkePublicKey::Create(
      public_key1.GetParameters(),
      public_key1.GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  EXPECT_TRUE(public_key1 != *public_key2);
  EXPECT_TRUE(*public_key2 != public_key1);
  EXPECT_FALSE(public_key1 == *public_key2);
  EXPECT_FALSE(*public_key2 == public_key1);
}

TEST(HpkePublicKeyTest, CopyConstructor) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& public_key = private_key.GetPublicKey();

  HpkePublicKey copy(public_key);

  EXPECT_THAT(copy, Eq(public_key));
}

TEST(HpkePublicKeyTest, CopyAssignment) {
  const auto& private_key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const auto& private_key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);
  const HpkePublicKey& key1 = private_key1.GetPublicKey();
  const HpkePublicKey& key2 = private_key2.GetPublicKey();

  HpkePublicKey copy = key2;
  copy = key1;

  EXPECT_THAT(copy, Eq(key1));
}

TEST(HpkePublicKeyTest, MoveConstructor) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  HpkePublicKey key = private_key.GetPublicKey();

  HpkePublicKey expected = key;
  HpkePublicKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(HpkePublicKeyTest, MoveAssignment) {
  const auto& private_key1 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const auto& private_key2 = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemP256HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kCrunchy)
           .hybrid_private_key);
  HpkePublicKey key1 = private_key1.GetPublicKey();
  HpkePublicKey key2 = private_key2.GetPublicKey();

  HpkePublicKey expected = key1;
  key2 = std::move(key1);

  EXPECT_THAT(key2, Eq(expected));
}

TEST(HpkePublicKeyTest, Clone) {
  const auto& private_key = dynamic_cast<const HpkePrivateKey&>(
      *GetHpkeTestVector(HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                         HpkeParameters::KdfId::kHkdfSha256,
                         HpkeParameters::AeadId::kAesGcm128,
                         HpkeParameters::Variant::kNoPrefix)
           .hybrid_private_key);
  const HpkePublicKey& key = private_key.GetPublicKey();

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key.Clone();

  ASSERT_THAT(*cloned_key, Eq(key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
