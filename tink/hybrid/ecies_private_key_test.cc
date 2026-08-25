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

#include "tink/hybrid/ecies_private_key.h"

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
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/subtle/random.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/hybrid/internal/testing/ecies_aead_hkdf_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateEciesTestVectors;
using ::crypto::tink::internal::HybridTestVector;
using ::crypto::tink::test::HexDecodeOrDie;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

std::vector<EciesPrivateKey> CreateTestKeys() {
  std::vector<EciesPrivateKey> keys;
  for (const HybridTestVector& vector : CreateEciesTestVectors()) {
    const EciesPrivateKey* private_key =
        dynamic_cast<const EciesPrivateKey*>(vector.hybrid_private_key.get());
    if (private_key->GetPublicKey().GetParameters().GetCurveType() ==
        EciesParameters::CurveType::kX25519) {
      continue;
    }
    keys.push_back(*private_key);
  }
  return keys;
}

using EciesPrivateKeyTest = TestWithParam<EciesPrivateKey>;

INSTANTIATE_TEST_SUITE_P(EciesPrivateKeyTestSuite, EciesPrivateKeyTest,
                         ValuesIn(CreateTestKeys()));

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKey) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();
  const EciesParameters& params = public_key.GetParameters();

  RestrictedData private_key_value =
      *static_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(params));
  EXPECT_THAT(private_key->GetIdRequirement(),
              Eq(static_key.GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(static_key.GetOutputPrefix()));
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_value));
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(
      private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
      Eq(RestrictedBigInteger(
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get()),
          InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(std::nullopt));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyFailsTooManyBytes) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();
  const EciesParameters& params = public_key.GetParameters();

  RestrictedData private_key_value =
      *static_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  // Add some bytes to the private key.
  RestrictedData extra_private_key_value = RestrictedData(
      absl::StrCat(std::string(params.GetPrivateKeyLength() -
                                   private_key_value.size() + 1,
                               '\x00'),
                   private_key_value.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForNistCurve(
                  public_key, extra_private_key_value, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyFailsTooFewBytes) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();

  RestrictedData private_key_value =
      *static_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  // Remove some bytes from the private key.
  int reduced_size =
      private_key_value.GetSecret(InsecureSecretKeyAccess::Get()).size() - 2;
  RestrictedData shortened_private_key_value =
      RestrictedData(private_key_value.GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, reduced_size),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurve(
          public_key, shortened_private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyAllowNonConstantTime) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();
  const EciesParameters& params = public_key.GetParameters();

  RestrictedData private_key_value =
      *static_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
          public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(params));
  EXPECT_THAT(private_key->GetIdRequirement(),
              Eq(static_key.GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(static_key.GetOutputPrefix()));
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_value));
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(
      private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
      Eq(RestrictedBigInteger(
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get()),
          InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(std::nullopt));
}

TEST(EciesPrivateKeyTest, CreateWithPrivateKeyWithLeadingZeros) {
  std::string public_x = HexDecodeOrDie(
      "bc95b9d6e70821a0bc477d7032085c780e2cae8fdf3d08508989f154b4c327d0");
  std::string public_y = HexDecodeOrDie(
      "6b7ae183d851aec7d1b81f3fb152aa5f661231953e0e4b7c99d14c3f671d3258");
  std::string private_key_bytes = HexDecodeOrDie(
      "005356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(public_x.length(), Eq(32));
  ASSERT_THAT(public_y.length(), Eq(32));
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
                  *public_key, private_key_value, GetPartialKeyAccess()),
              IsOk());
}

TEST(EciesPrivateKeyTest, CreateWithPrivateKeyWithOneTooManyBytes) {
  std::string public_x = HexDecodeOrDie(
      "bc95b9d6e70821a0bc477d7032085c780e2cae8fdf3d08508989f154b4c327d0");
  std::string public_y = HexDecodeOrDie(
      "6b7ae183d851aec7d1b81f3fb152aa5f661231953e0e4b7c99d14c3f671d3258");
  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "ff5356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("too large")));
}

TEST(EciesPrivateKeyTest, CreateWithPrivateKeyWithOneTooFewBytes) {
  std::string public_x = HexDecodeOrDie(
      "5e06e5dc416789b2377a305132455025354d27eec2420c30a0b1658503e14780");
  std::string public_y = HexDecodeOrDie(
      "f43e6af3ef0dabe891693cefc8bf3fe51733a02e19a6fa418a21fc2040ea1b92");
  // Private key with 31 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "68e0e126325d313dd9cf888e1163c9844cc6f9d9e41ae075338d34e2878cb9");
  ASSERT_THAT(public_x.length(), Eq(32));
  ASSERT_THAT(public_y.length(), Eq(32));
  ASSERT_THAT(private_key_bytes.length(), Eq(31));

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kNistP256)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetNistCurvePointFormat(EciesParameters::PointFormat::kUncompressed)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         /*id_requirement=*/123,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 31 is different from expected length 32")));
  EXPECT_THAT(EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
                  *public_key, private_key_value, GetPartialKeyAccess()),
              IsOk());
}

TEST(EciesPrivateKeyTest, CreateX25519PrivateKey) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  const EciesPrivateKey& static_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  std::string public_key_bytes =
      std::string(*static_key.GetPublicKey().GetX25519CurvePointBytes(
          GetPartialKeyAccess()));
  RestrictedData private_key_bytes =
      *static_key.GetX25519PrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), IsEmpty());
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
              Eq(absl::nullopt));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(std::nullopt));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST_P(EciesPrivateKeyTest, CreateMismatchedNistCurveKeyPairFails) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();
  const EciesParameters& params = public_key.GetParameters();

  int private_key_length = params.GetPrivateKeyLength();
  RestrictedData private_key_bytes =
      RestrictedData(subtle::Random::GetRandomBytes(private_key_length),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForNistCurve(public_key, private_key_bytes,
                                                  GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPrivateKeyTest, CreateMismatchedX25519KeyPairFails) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  const EciesPrivateKey& static_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  std::string public_key_bytes =
      std::string(*static_key.GetPublicKey().GetX25519CurvePointBytes(
          GetPartialKeyAccess()));
  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Use a different private key from cached key.
  int private_key_length = params->GetPrivateKeyLength();
  RestrictedData private_key_bytes =
      RestrictedData(subtle::Random::GetRandomBytes(private_key_length),
                     InsecureSecretKeyAccess::Get());
  EXPECT_THAT(EciesPrivateKey::CreateForCurveX25519(
                  *public_key, private_key_bytes, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EciesPrivateKeyTest, CreateX25519PrivateKeyWithInvalidKeyLengthFails) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  const EciesPrivateKey& static_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  std::string public_key_bytes =
      std::string(*static_key.GetPublicKey().GetX25519CurvePointBytes(
          GetPartialKeyAccess()));
  std::string private_key_input =
      std::string(static_key.GetX25519PrivateKeyBytes(GetPartialKeyAccess())
                      ->GetSecret(InsecureSecretKeyAccess::Get()));
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(test::HexDecodeOrDie("00"), private_key_input),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(
      EciesPrivateKey::CreateForCurveX25519(
          *public_key, expanded_private_key_bytes, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, GetPrivateKeyLengthNistCurve) {
  const EciesPrivateKey& static_key = GetParam();
  const EciesPublicKey& public_key = static_key.GetPublicKey();
  const EciesParameters& params = public_key.GetParameters();

  RestrictedData private_key_value =
      *static_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(
      private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess())->size(),
      Eq(params.GetPrivateKeyLength()));
}

TEST(EciesPrivateKeyTest, GetPrivateKeyLengthX25519Curve) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  const EciesPrivateKey& static_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  std::string public_key_bytes =
      std::string(*static_key.GetPublicKey().GetX25519CurvePointBytes(
          GetPartialKeyAccess()));
  RestrictedData private_key_bytes =
      *static_key.GetX25519PrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/std::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(
      private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess())->size(),
      Eq(params->GetPrivateKeyLength()));
}

TEST_P(EciesPrivateKeyTest, NistCurvePrivateKeyEquals) {
  const EciesPrivateKey& private_key = GetParam();
  if (private_key.GetPublicKey().GetParameters().GetCurveType() ==
      EciesParameters::CurveType::kX25519) {
    return;
  }
  RestrictedData private_key_value =
      *private_key.GetNistPrivateKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForNistCurve(
          private_key.GetPublicKey(), private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == private_key);
  EXPECT_FALSE(private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != private_key);
}

TEST(EciesPrivateKeyTest, X25519PrivateKeyEquals) {
  const EciesPrivateKey& private_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  EciesPrivateKey other_private_key = private_key;

  EXPECT_TRUE(private_key == other_private_key);
  EXPECT_TRUE(other_private_key == private_key);
  EXPECT_FALSE(private_key != other_private_key);
  EXPECT_FALSE(other_private_key != private_key);
}

TEST(EciesPrivateKeyTest, DifferentPublicKeyNotEqual) {
  const EciesPrivateKey& key1 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256);
  const EciesPrivateKey& key2 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P384);

  EXPECT_TRUE(key1 != key2);
  EXPECT_TRUE(key2 != key1);
  EXPECT_FALSE(key1 == key2);
  EXPECT_FALSE(key2 == key1);
}

TEST(EciesPrivateKeyTest, DifferentKeyTypesNotEqual) {
  const EciesPrivateKey& private_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  const EciesPublicKey& public_key = private_key.GetPublicKey();

  EXPECT_TRUE(private_key != public_key);
  EXPECT_TRUE(public_key != private_key);
  EXPECT_FALSE(private_key == public_key);
  EXPECT_FALSE(public_key == private_key);
}

TEST(EciesPrivateKeyTest, CopyConstructor) {
  const EciesPrivateKey& private_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  EciesPrivateKey copy(private_key);
  EXPECT_THAT(copy, Eq(private_key));
}

TEST(EciesPrivateKeyTest, CopyAssignment) {
  const EciesPrivateKey& key1 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  const EciesPrivateKey& key2 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256);

  EciesPrivateKey copy = key2;
  copy = key1;

  EXPECT_THAT(copy, Eq(key1));
}

TEST(EciesPrivateKeyTest, MoveConstructor) {
  const EciesPrivateKey& private_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  EciesPrivateKey copy_to_move = private_key;
  EciesPrivateKey moved(std::move(copy_to_move));

  EXPECT_THAT(moved, Eq(private_key));
}

TEST(EciesPrivateKeyTest, MoveAssignment) {
  const EciesPrivateKey& key1 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  const EciesPrivateKey& key2 =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::NIST_P256);
  EciesPrivateKey copy_to_move = key1;
  EciesPrivateKey moved = key2;
  moved = std::move(copy_to_move);

  EXPECT_THAT(moved, Eq(key1));
}

TEST(EciesPrivateKeyTest, Clone) {
  const EciesPrivateKey& private_key =
      *internal::GetEciesPrivateKey(subtle::EllipticCurveType::CURVE25519);
  std::unique_ptr<Key> cloned_key = private_key.Clone();

  ASSERT_THAT(*cloned_key, Eq(private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
