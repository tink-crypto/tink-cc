// Copyright 2025 Google LLC
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

#include "tink/experimental/pqcrypto/kem/cecpq2_private_key.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "openssl/hrss.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  Cecpq2Parameters::Variant variant;
  absl::optional<int> id_requirement;
};

using Cecpq2PrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    Cecpq2PrivateKeyTests, Cecpq2PrivateKeyTest,
    Values(TestCase{Cecpq2Parameters::Variant::kTink, 0x02030400},
           TestCase{Cecpq2Parameters::Variant::kNoPrefix, absl::nullopt}));

TEST_P(Cecpq2PrivateKeyTest, Build) {
  TestCase test_case = GetParam();

  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*dem_parameters, "salt", test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(x25519_private_key_bytes));
  EXPECT_THAT(private_key->GetHrssPrivateKeySeed(GetPartialKeyAccess()),
              Eq(hrss_private_key_seed));
}

TEST(Cecpq2PrivateKeyTest, BuildWithMissingPublicKey) {
  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(private_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("CECPQ2 public key must be set")));
}

TEST(Cecpq2PrivateKeyTest, BuildWithMissingX25519PrivateKey) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(private_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("X25519 private key must be set")));
}

TEST(Cecpq2PrivateKeyTest, BuildWithInvalidX25519PrivateKey) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(
      subtle::Random::GetRandomBytes(internal::X25519KeyPrivKeySize()),
      InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(private_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("X25519 private key does not match")));
}

TEST(Cecpq2PrivateKeyTest, BuildWithMissingHrssPrivateKey) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(private_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HRSS private key seed must be set")));
}

TEST(Cecpq2PrivateKeyTest, BuildWithInvalidHrssPrivateKey) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      subtle::Random::GetRandomBytes(HRSS_PRIVATE_KEY_BYTES),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(private_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HRSS private seed does not match")));
}

TEST_P(Cecpq2PrivateKeyTest, PrivateKeysEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*dem_parameters, "salt", test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<Cecpq2PrivateKey> other_private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(Cecpq2PrivateKeyTest, DifferentPublicKeysNotEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key1 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key2 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(2)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<Cecpq2PrivateKey> other_private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key2)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(Cecpq2PrivateKeyTest, CopyConstructor) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  Cecpq2PrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(Cecpq2PrivateKeyTest, CopyAssignment) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key1 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key2 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(2)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<Cecpq2PrivateKey> copy =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key2)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());
  EXPECT_THAT(*copy, Not(Eq(*private_key)));

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(Cecpq2PrivateKeyTest, MoveConstructor) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  Cecpq2PrivateKey move(std::move(*private_key));

  EXPECT_THAT(move.GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(move.GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(x25519_private_key_bytes));
  EXPECT_THAT(move.GetHrssPrivateKeySeed(GetPartialKeyAccess()),
              Eq(hrss_private_key_seed));
}

TEST(Cecpq2PrivateKeyTest, MoveAssignment) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key1 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key2 =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(2)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<Cecpq2PrivateKey> move =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key2)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());
  EXPECT_THAT(*move, Not(Eq(*private_key)));

  *move = std::move(*private_key);

  EXPECT_THAT(move->GetPublicKey(), Eq(*public_key1));
  EXPECT_THAT(move->GetX25519PrivateKeyBytes(GetPartialKeyAccess()),
              Eq(x25519_private_key_bytes));
  EXPECT_THAT(move->GetHrssPrivateKeySeed(GetPartialKeyAccess()),
              Eq(hrss_private_key_seed));
}

TEST(Cecpq2PrivateKeyTest, Clone) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .SetIdRequirement(1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  std::unique_ptr<Key> clone = private_key->Clone();

  EXPECT_THAT(*clone, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
