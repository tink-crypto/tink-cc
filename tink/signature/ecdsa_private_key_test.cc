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

#include "tink/signature/ecdsa_private_key.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/util/test_util.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  subtle::EllipticCurveType curve;
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using EcdsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaPrivateKeyTestSuite, EcdsaPrivateKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""},
           TestCase{subtle::EllipticCurveType::NIST_P256,
                    EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kNoPrefixWithPrehashId,
                    /*id_requirement=*/0x123,
                    /*output_prefix=*/""}));

template <typename PrivateKeyType>
void CreatePrivateKeyAndCheck(const TestCase& test_case,
                              const internal::EcKey& ec_key,
                              const PrivateKeyType& private_key_value) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point(BigInteger(ec_key.pub_x), BigInteger(ec_key.pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // NOLINTNEXTLINE(clang-diagnostic-deprecated-declarations)
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(RestrictedData(util::SecretDataAsStringView(ec_key.priv),
                                InsecureSecretKeyAccess::Get())));
}

TEST_P(EcdsaPrivateKeyTest, CreatePrivateKeyWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());
  CreatePrivateKeyAndCheck(test_case, *ec_key, private_key_value);
}

TEST_P(EcdsaPrivateKeyTest, CreatePrivateKeyWithRestrictedBigIntegerWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());
  CreatePrivateKeyAndCheck(test_case, *ec_key, private_key_value);
}

TEST_P(EcdsaPrivateKeyTest, CreatePrivateKeyAllowNonConstantTimeWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPrivateKey> private_key =
      EcdsaPrivateKey::CreateAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKey(GetPartialKeyAccess()),
              Eq(private_key_value));
}

TEST(EcdsaPrivateKeyTest, CreateWithPrivateKeyWithLeadingZeros) {
  std::string public_x = HexDecodeOrDie(
      "bc95b9d6e70821a0bc477d7032085c780e2cae8fdf3d08508989f154b4c327d0");
  std::string public_y = HexDecodeOrDie(
      "6b7ae183d851aec7d1b81f3fb152aa5f661231953e0e4b7c99d14c3f671d3258");
  std::string private_key_bytes = HexDecodeOrDie(
      "005356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(public_x.length(), Eq(32));
  ASSERT_THAT(public_y.length(), Eq(32));
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EcdsaPrivateKey::Create(*public_key, private_key_value,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(EcdsaPrivateKey::CreateAllowNonConstantTime(
                  *public_key, private_key_value, GetPartialKeyAccess())
                  .status(),
              IsOk());
}

TEST(EcdsaPrivateKeyTest, CreateWithPrivateKeyWithOneTooManyBytes) {
  std::string public_x = HexDecodeOrDie(
      "bc95b9d6e70821a0bc477d7032085c780e2cae8fdf3d08508989f154b4c327d0");
  std::string public_y = HexDecodeOrDie(
      "6b7ae183d851aec7d1b81f3fb152aa5f661231953e0e4b7c99d14c3f671d3258");
  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "ff5356ba39d3d19daab9f2146ae03f5c9b7f2f69a219356b2283977a5e55e5d0b8");
  ASSERT_THAT(private_key_bytes.length(), Eq(33));

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EcdsaPrivateKey::Create(*public_key, private_key_value,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 33 is different from expected length 32")));
  EXPECT_THAT(
      EcdsaPrivateKey::CreateAllowNonConstantTime(
          *public_key, private_key_value, GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Private key is too long and has a non-zero leading byte.")));
}

TEST(EcdsaPrivateKeyTest, CreateWithPrivateKeyWithOneTooFewBytes) {
  std::string public_x = HexDecodeOrDie(
      "5e06e5dc416789b2377a305132455025354d27eec2420c30a0b1658503e14780");
  std::string public_y = HexDecodeOrDie(
      "f43e6af3ef0dabe891693cefc8bf3fe51733a02e19a6fa418a21fc2040ea1b92");
  // Private key with 33 bytes (NIST P-256 takes 32 bytes).
  std::string private_key_bytes = HexDecodeOrDie(
      "68e0e126325d313dd9cf888e1163c9844cc6f9d9e41ae075338d34e2878cb9");
  ASSERT_THAT(public_x.length(), Eq(32));
  ASSERT_THAT(public_y.length(), Eq(32));
  ASSERT_THAT(private_key_bytes.length(), Eq(31));

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point((BigInteger(public_x)), BigInteger(public_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      EcdsaPrivateKey::Create(*public_key, private_key_value,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          StrEq("Private key length 31 is different from expected length 32")));
  EXPECT_THAT(EcdsaPrivateKey::CreateAllowNonConstantTime(
                  *public_key, private_key_value, GetPartialKeyAccess())
                  .status(),
              IsOk());
}

TEST_P(EcdsaPrivateKeyTest, CreateMismatchedKeyPairFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key1 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key1, IsOk());

  EcPoint public_point(BigInteger(ec_key1->pub_x), BigInteger(ec_key1->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key1 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<internal::EcKey> ec_key2 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedData private_key_bytes2 =
      RestrictedData(util::SecretDataAsStringView(ec_key2->priv),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(EcdsaPrivateKey::Create(*public_key1, private_key_bytes2,
                                      GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid EC key pair")));
}

TEST_P(EcdsaPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EcdsaPrivateKey> other_private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST_P(EcdsaPrivateKeyTest, CopyAssign) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<EcdsaPrivateKey> key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<internal::EcKey> other_ec_key =
      internal::NewEcKey(test_case.curve);
  ASSERT_THAT(other_ec_key, IsOk());
  EcPoint other_public_point(BigInteger(other_ec_key->pub_x),
                             BigInteger(other_ec_key->pub_y));
  absl::StatusOr<EcdsaPublicKey> other_public_key =
      EcdsaPublicKey::Create(*parameters, other_public_point,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());
  RestrictedData other_private_key_value =
      RestrictedData(util::SecretDataAsStringView(other_ec_key->priv),
                     InsecureSecretKeyAccess::Get());
  absl::StatusOr<EcdsaPrivateKey> other_key = EcdsaPrivateKey::Create(
      *other_public_key, other_private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_THAT(*key, Not(Eq(*other_key)));

  *other_key = *key;
  EXPECT_THAT(*key, Eq(*other_key));
}

TEST(EcdsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key1 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key2 =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key1, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EcdsaPrivateKey> other_private_key = EcdsaPrivateKey::Create(
      *public_key2, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(EcdsaPrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(EcdsaPrivateKeyTest, Clone) {
  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_value =
      RestrictedData(util::SecretDataAsStringView(ec_key->priv),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
