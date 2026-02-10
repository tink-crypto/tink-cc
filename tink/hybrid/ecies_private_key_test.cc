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
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/restricted_big_integer.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  subtle::EllipticCurveType curve;
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  subtle::EcPointFormat ec_point_format;
  EciesParameters::PointFormat point_format;
  EciesParameters::DemId dem_id;
  EciesParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using EciesPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EciesPrivateKeyTestSuite, EciesPrivateKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    EciesParameters::CurveType::kNistP256,
                    EciesParameters::HashType::kSha256,
                    subtle::EcPointFormat::COMPRESSED,
                    EciesParameters::PointFormat::kCompressed,
                    EciesParameters::DemId::kAes128GcmRaw,
                    EciesParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EciesParameters::CurveType::kNistP384,
                    EciesParameters::HashType::kSha384,
                    subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                    EciesParameters::PointFormat::kLegacyUncompressed,
                    EciesParameters::DemId::kAes256GcmRaw,
                    EciesParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    EciesParameters::CurveType::kNistP521,
                    EciesParameters::HashType::kSha512,
                    subtle::EcPointFormat::UNCOMPRESSED,
                    EciesParameters::PointFormat::kUncompressed,
                    EciesParameters::DemId::kAes256SivRaw,
                    EciesParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKey) {
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_value));
  EXPECT_THAT(
      private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
      Eq(RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                              InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(absl::nullopt));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyFailsTooManyBytes) {
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  // Add some bytes to the private key.
  RestrictedData extra_private_key_value = RestrictedData(
      absl::StrCat(
          std::string(public_key->GetParameters().GetPrivateKeyLength() -
                          private_key_value.size() + 1,
                      '\x00'),
          private_key_value.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForNistCurve(
                  *public_key, extra_private_key_value, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyFailsTooFewBytes) {
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  // Remove some bytes from the private key.
  int reduced_size =
      private_key_value.GetSecret(InsecureSecretKeyAccess::Get()).size() - 2;
  RestrictedData shortened_private_key_value =
      RestrictedData(private_key_value.GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, reduced_size),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EciesPrivateKey::CreateForNistCurve(
          *public_key, shortened_private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, CreateNistCurvePrivateKeyAllowNonConstantTime) {
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurveAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_value));
  EXPECT_THAT(
      private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
      Eq(RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                              InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(absl::nullopt));
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
                  *public_key, private_key_value, GetPartialKeyAccess())
                  .status(),
              IsOk());
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

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), IsEmpty());
  EXPECT_THAT(private_key->GetNistPrivateKeyValue(GetPartialKeyAccess()),
              Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST_P(EciesPrivateKeyTest, CreateMismatchedNistCurveKeyPairFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key1 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  absl::StatusOr<EciesPublicKey> public_key1 =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<internal::EcKey> ec_key2 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedData private_key_bytes2 =
      RestrictedData(util::SecretDataAsStringView(ec_key2->priv),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EciesPrivateKey::CreateForNistCurve(
                  *public_key1, private_key_bytes2, GetPartialKeyAccess())
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

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(32), InsecureSecretKeyAccess::Get());

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

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  std::string private_key_input =
      std::string(util::SecretDataAsStringView((*x25519_key)->private_key));
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(test::HexDecodeOrDie("00"), private_key_input),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(
      EciesPrivateKey::CreateForCurveX25519(
          *public_key, expanded_private_key_bytes, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(EciesPrivateKeyTest, GetPrivateKeyLengthNistCurve) {
  TestCase test_case = GetParam();
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(
      private_key->GetNistPrivateKeyBytes(GetPartialKeyAccess())->size(),
      Eq(params->GetPrivateKeyLength()));
}

TEST_P(EciesPrivateKeyTest, GetPrivateKeyLengthX25519Curve) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
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
  TestCase test_case = GetParam();

  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetNistCurvePointFormat(test_case.point_format)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForNistCurve(*params, public_point,
                                         test_case.id_requirement,
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForNistCurve(*public_key, private_key_value,
                                          GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(EciesPrivateKeyTest, X25519PrivateKeyEquals) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(EciesPrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key123 =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  absl::StatusOr<EciesPublicKey> public_key456 =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/456,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key123, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesPrivateKey> other_private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key456, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(EciesPrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(EciesPrivateKeyTest, CopyConstructor) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EciesPrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(EciesPrivateKeyTest, CopyAssignment) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesParameters> other_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> other_x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(other_x25519_key, IsOk());

  std::string other_public_key_bytes = std::string(
      reinterpret_cast<const char*>((*other_x25519_key)->public_value),
      internal::X25519KeyPubKeySize());
  RestrictedData other_private_key_bytes = RestrictedData(
      (*other_x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(
          *other_params, other_public_key_bytes,
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> copy = EciesPrivateKey::CreateForCurveX25519(
      *other_public_key, other_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(EciesPrivateKeyTest, MoveConstructor) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EciesPrivateKey expected = *private_key;
  EciesPrivateKey moved(std::move(*private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(EciesPrivateKeyTest, MoveAssignment) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/123,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesParameters> other_params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes128GcmRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> other_x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(other_x25519_key, IsOk());

  std::string other_public_key_bytes = std::string(
      reinterpret_cast<const char*>((*other_x25519_key)->public_value),
      internal::X25519KeyPubKeySize());
  RestrictedData other_private_key_bytes = RestrictedData(
      (*other_x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> other_public_key =
      EciesPublicKey::CreateForCurveX25519(
          *other_params, other_public_key_bytes,
          /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> moved = EciesPrivateKey::CreateForCurveX25519(
      *other_public_key, other_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  EciesPrivateKey expected = *private_key;
  *moved = std::move(*private_key);

  EXPECT_THAT(*moved, Eq(expected));
}

TEST(EciesPrivateKeyTest, Clone) {
  absl::StatusOr<EciesParameters> params =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*params, public_key_bytes,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(*public_key, private_key_bytes,
                                            GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
