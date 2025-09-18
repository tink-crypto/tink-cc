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

#include "tink/hybrid/hpke_private_key.h"

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
#include "tink/internal/secret_buffer.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#include "openssl/ec_key.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/xwing_util.h"
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

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  subtle::EllipticCurveType curve;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  HpkeParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using HpkePrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HpkePrivateKeyTestSuite, HpkePrivateKeyTest,
    Values(TestCase{subtle::EllipticCurveType::NIST_P256,
                    HpkeParameters::KemId::kDhkemP256HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kAesGcm128,
                    HpkeParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P384,
                    HpkeParameters::KemId::kDhkemP384HkdfSha384,
                    HpkeParameters::KdfId::kHkdfSha384,
                    HpkeParameters::AeadId::kAesGcm256,
                    HpkeParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{subtle::EllipticCurveType::NIST_P521,
                    HpkeParameters::KemId::kDhkemP521HkdfSha512,
                    HpkeParameters::KdfId::kHkdfSha512,
                    HpkeParameters::AeadId::kChaCha20Poly1305,
                    HpkeParameters::Variant::kNoPrefix,
                    /*id_requirement=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(HpkePrivateKeyTest, CreateNistCurvePrivateKey) {
  TestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  absl::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes(ec_key->priv,
                                   InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
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

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData private_key_bytes = RestrictedData(
      (*x25519_key)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
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

  absl::StatusOr<internal::XWingKey> xwing_key = internal::NewXWingKey();
  ASSERT_THAT(xwing_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>(xwing_key->public_key.data()),
                  xwing_key->public_key.size());
  RestrictedData private_key_bytes =
      RestrictedData(xwing_key->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*params));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(private_key_bytes));
}

TEST_P(HpkePrivateKeyTest, CreateMismatchedNistCurveKeyPairFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key1 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key1, IsOk());
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point1 =
      internal::GetEcPoint(test_case.curve, ec_key1->pub_x, ec_key1->pub_y);
  ASSERT_THAT(ec_point1, IsOk());
  absl::StatusOr<std::string> public_key_bytes1 = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point1->get());
  ASSERT_THAT(public_key_bytes1, IsOk());

  absl::StatusOr<HpkePublicKey> public_key1 =
      HpkePublicKey::Create(*params, *public_key_bytes1,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<internal::EcKey> ec_key2 = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key2, IsOk());

  RestrictedData private_key_bytes2(ec_key2->priv,
                                    InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key1, private_key_bytes2,
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

  std::string public_key_bytes = subtle::Random::GetRandomBytes(32);
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(32), InsecureSecretKeyAccess::Get());

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

  std::string public_key_bytes = subtle::Random::GetRandomBytes(1216);
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(32), InsecureSecretKeyAccess::Get());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePrivateKeyTest, CreateNistPrivateKeyWithInvalidKeyLengthFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  absl::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  internal::SecretBuffer private_key_input =
      util::internal::AsSecretBuffer(ec_key->priv);
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

  absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
      internal::NewX25519Key();
  ASSERT_THAT(x25519_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                  internal::X25519KeyPubKeySize());
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView((*x25519_key)->private_key)),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/absl::nullopt,
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

  absl::StatusOr<internal::XWingKey> xwing_key = internal::NewXWingKey();
  ASSERT_THAT(xwing_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>(xwing_key->public_key.data()),
                  xwing_key->public_key.size());
  RestrictedData expanded_private_key_bytes = RestrictedData(
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(xwing_key->private_key)),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(HpkePrivateKey::Create(*public_key, expanded_private_key_bytes,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkePrivateKeyTest, NistCurvePrivateKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<HpkeParameters> params = HpkeParameters::Builder()
                                              .SetVariant(test_case.variant)
                                              .SetKemId(test_case.kem_id)
                                              .SetKdfId(test_case.kdf_id)
                                              .SetAeadId(test_case.aead_id)
                                              .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(test_case.curve, ec_key->pub_x, ec_key->pub_y);
  ASSERT_THAT(ec_point, IsOk());
  absl::StatusOr<std::string> public_key_bytes = internal::EcPointEncode(
      test_case.curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  ASSERT_THAT(public_key_bytes, IsOk());

  RestrictedData private_key_bytes(ec_key->priv,
                                   InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, *public_key_bytes,
                            test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<HpkePrivateKey> other_private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(HpkePrivateKeyTest, X25519PrivateKeyEquals) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
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

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<HpkePrivateKey> other_private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(HpkePrivateKeyTest, XWingPrivateKeyEquals) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<internal::XWingKey> xwing_key = internal::NewXWingKey();
  ASSERT_THAT(xwing_key, IsOk());

  std::string public_key_bytes =
      std::string(reinterpret_cast<const char*>(xwing_key->public_key.data()),
                  xwing_key->public_key.size());
  RestrictedData private_key_bytes =
      RestrictedData(xwing_key->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<HpkePrivateKey> other_private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(HpkePrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
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

  absl::StatusOr<HpkePublicKey> public_key123 =
      HpkePublicKey::Create(*params, public_key_bytes,
                            /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  absl::StatusOr<HpkePublicKey> public_key456 =
      HpkePublicKey::Create(*params, public_key_bytes,
                            /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key123, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<HpkePrivateKey> other_private_key = HpkePrivateKey::Create(
      *public_key456, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(HpkePrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
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

  absl::StatusOr<HpkePublicKey> public_key =
      HpkePublicKey::Create(*params, public_key_bytes,
                            /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(HpkePrivateKeyTest, Clone) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kChaCha20Poly1305)
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

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *params, public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
