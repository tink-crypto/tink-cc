// Copyright 2024 Google LLC
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

#include "tink/hybrid/ecies_public_key.h"

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
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/testing/ec_test_vectors.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateEciesTestVectors;
using ::crypto::tink::internal::GetEciesPrivateKey;
using ::crypto::tink::internal::HybridTestVector;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Pointee;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

std::vector<EciesPublicKey> CreateTestKeys() {
  std::vector<EciesPublicKey> keys;
  for (const HybridTestVector& vector : CreateEciesTestVectors()) {
    const EciesPrivateKey* private_key =
        dynamic_cast<const EciesPrivateKey*>(vector.hybrid_private_key.get());
    if (private_key->GetPublicKey().GetParameters().GetCurveType() ==
        EciesParameters::CurveType::kX25519) {
      continue;
    }
    keys.push_back(private_key->GetPublicKey());
  }
  return keys;
}

using EciesPublicKeyTest = TestWithParam<EciesPublicKey>;

INSTANTIATE_TEST_SUITE_P(EciesPublicKeyTestSuite, EciesPublicKeyTest,
                         ValuesIn(CreateTestKeys()));

TEST_P(EciesPublicKeyTest, CreateNistCurvePublicKey) {
  const EciesPublicKey& static_public_key = GetParam();
  const EciesParameters& params = static_public_key.GetParameters();

  EcPoint public_point =
      *static_public_key.GetNistCurvePoint(GetPartialKeyAccess());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(params, public_point,
                                         static_public_key.GetIdRequirement(),
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(params));
  EXPECT_THAT(public_key->GetIdRequirement(),
              Eq(static_public_key.GetIdRequirement()));
  EXPECT_THAT(public_key->GetOutputPrefix(),
              Eq(static_public_key.GetOutputPrefix()));
  EXPECT_THAT(public_key->GetNistCurvePoint(GetPartialKeyAccess()),
              Eq(public_point));
  EXPECT_THAT(public_key->GetX25519CurvePointBytes(GetPartialKeyAccess()),
              Eq(std::nullopt));
}

TEST(EciesPublicKeyTest, CreateX25519PublicKey) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*params));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(public_key->GetOutputPrefix(), IsEmpty());
  EXPECT_THAT(public_key->GetNistCurvePoint(GetPartialKeyAccess()),
              Eq(std::nullopt));
  EXPECT_THAT(public_key->GetX25519CurvePointBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST(EciesPublicKeyTest, CreateX25519PublicKeyWithInvalidLength) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(
          *params, public_key_bytes.substr(0, public_key_bytes.size() - 1),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPublicKeyTest, CreateNistCurvePublicKeyWithInvalidPoint) {
  // Copied from "public point not on curve" Wycheproof test case in
  //
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
  ASSERT_THAT(public_key_bytes, SizeIs(65));
  ASSERT_THAT(public_key_bytes[0], Eq(0x04));

  BigInteger x(public_key_bytes.substr(1, 32));
  BigInteger y(public_key_bytes.substr(33, 32));
  EcPoint point(x, y);

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, point,
                                         /*id_requirement=*/std::nullopt,
                                         GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST(EciesPublicKeyTest,
     CreateX2559CurvePublicKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<EciesParameters> no_prefix_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<EciesParameters> tink_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  EXPECT_THAT(EciesPublicKey::CreateForCurveX25519(
                  *no_prefix_params, public_key_bytes,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(EciesPublicKey::CreateForCurveX25519(
                  *tink_params, public_key_bytes,
                  /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPublicKeyTest,
     CreateNistCurvePublicKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<EciesParameters> no_prefix_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<EciesParameters> tink_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  const internal::EcKey& ec_key =
      internal::GetEcKey(subtle::EllipticCurveType::NIST_P256);
  EcPoint public_point(BigInteger(ec_key.pub_x), BigInteger(ec_key.pub_y));

  EXPECT_THAT(EciesPublicKey::CreateForNistCurve(
                  *no_prefix_params, public_point,
                  /*id_requirement=*/123, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(EciesPublicKey::CreateForNistCurve(
                  *tink_params, public_point,
                  /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPublicKeyTest, NistCurvePublicKeyEquals) {
  const EciesPublicKey& public_key = GetParam();
  if (public_key.GetParameters().GetCurveType() ==
      EciesParameters::CurveType::kX25519) {
    return;
  }
  EcPoint public_point = *public_key.GetNistCurvePoint(GetPartialKeyAccess());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForNistCurve(
          public_key.GetParameters(), public_point,
          public_key.GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == public_key);
  EXPECT_FALSE(public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != public_key);
}

TEST(EciesPublicKeyTest, X25519PublicKeyEquals) {
  const EciesPublicKey& public_key =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  EciesPublicKey other_public_key = public_key;

  EXPECT_TRUE(public_key == other_public_key);
  EXPECT_TRUE(other_public_key == public_key);
  EXPECT_FALSE(public_key != other_public_key);
  EXPECT_FALSE(other_public_key != public_key);
}

TEST(EciesPublicKeyTest, DifferentParametersNotEqual) {
  const EciesPublicKey& public_key1 =
      GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256)->GetPublicKey();
  const EciesPublicKey& public_key2 =
      GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P384)->GetPublicKey();

  EXPECT_TRUE(public_key1 != public_key2);
  EXPECT_TRUE(public_key2 != public_key1);
  EXPECT_FALSE(public_key1 == public_key2);
  EXPECT_FALSE(public_key2 == public_key1);
}

TEST(EciesPublicKeyTest, DifferentPublicPointsNotEqual) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  EcPoint public_point1 = internal::P256Point();
  EcPoint public_point2(
      BigInteger(test::HexDecodeOrDie(
          "98824439f3da0225096afe049e8e6db7273c7be13cfa1dfb1daefb7dad843ee3")),
      BigInteger(test::HexDecodeOrDie(
          "5aee5bf9e27efa148821f220442cb49a665326a465a8b806ab58c6fad546b496")));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point1,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point2,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes1 = subtle::Random::GetRandomBytes(32);
  std::string public_key_bytes2 = subtle::Random::GetRandomBytes(32);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes1,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes2,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/0x01020304,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/0x02030405,
                                           GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EciesPublicKeyTest, CopyConstructor) {
  const EciesPublicKey& public_key =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  EciesPublicKey copy(public_key);
  EXPECT_THAT(copy, Eq(public_key));
}

TEST(EciesPublicKeyTest, CopyAssignment) {
  const EciesPublicKey& key1 =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  const EciesPublicKey& key2 =
      GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256)->GetPublicKey();

  EciesPublicKey copy = key2;
  copy = key1;

  EXPECT_THAT(copy, Eq(key1));
}

TEST(EciesPublicKeyTest, MoveConstructor) {
  const EciesPublicKey& public_key =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  EciesPublicKey copy_to_move = public_key;
  EciesPublicKey moved(std::move(copy_to_move));

  EXPECT_THAT(moved, Eq(public_key));
}

TEST(EciesPublicKeyTest, MoveAssignment) {
  const EciesPublicKey& key1 =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  const EciesPublicKey& key2 =
      GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256)->GetPublicKey();
  EciesPublicKey copy_to_move = key1;
  EciesPublicKey moved = key2;
  moved = std::move(copy_to_move);

  EXPECT_THAT(moved, Eq(key1));
}

TEST(EciesPublicKeyTest, Clone) {
  const EciesPublicKey& public_key =
      GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519)->GetPublicKey();
  std::unique_ptr<Key> cloned_key = public_key.Clone();

  ASSERT_THAT(cloned_key, Pointee(Eq(public_key)));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
