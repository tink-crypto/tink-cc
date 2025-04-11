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

#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "openssl/hrss.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/internal/ec_util.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
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
  std::string output_prefix;
};

using Cecpq2PublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    Cecpq2PublicKeyTests, Cecpq2PublicKeyTest,
    Values(TestCase{Cecpq2Parameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Cecpq2Parameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(Cecpq2PublicKeyTest, Build) {
  TestCase test_case = GetParam();

  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(*dem_parameters, "salt", test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetX25519PublicKeyBytes(GetPartialKeyAccess()),
              Eq(x25519_public_key_bytes));
  EXPECT_THAT(public_key->GetHrssPublicKeyBytes(GetPartialKeyAccess()),
              Eq(hrss_public_key_bytes));
}

TEST(Cecpq2PublicKeyTest, BuildWithMissingParametersFails) {
  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(public_key, StatusIs(absl::StatusCode::kInvalidArgument,
                                   HasSubstr("CECPQ2 parameters must be set")));
}

TEST(Cecpq2PublicKeyTest, BuildWithMissingX25519PublicKeyFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(public_key, StatusIs(absl::StatusCode::kInvalidArgument,
                                   HasSubstr("X25519 public key must be set")));
}

TEST(Cecpq2PublicKeyTest, BuildWithInvalidX25519PublicKeyFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize() + 1);
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(public_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid X25519 public key length")));
}

TEST(Cecpq2PublicKeyTest, BuildWithMissingHrssPublicKeyFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(public_key, StatusIs(absl::StatusCode::kInvalidArgument,
                                   HasSubstr("HRSS public key must be set")));
}

TEST(Cecpq2PublicKeyTest, BuildWithInvalidHrssPublicKeyFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES + 1);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(public_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid HRSS public key length")));
}

TEST(Cecpq2PublicKeyTest, BuildWithInvalidIdRequirementFails) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2Parameters> no_prefix_parameters =
      Cecpq2Parameters::Create(*dem_parameters, "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_parameters, IsOk());

  absl::StatusOr<Cecpq2PublicKey> no_prefix_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*no_prefix_parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(no_prefix_public_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement")));

  absl::StatusOr<Cecpq2Parameters> tink_parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());

  absl::StatusOr<Cecpq2PublicKey> tink_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*tink_parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  EXPECT_THAT(tink_public_key,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement")));
}

TEST(Cecpq2PublicKeyTest, PublicKeysEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> other_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(Cecpq2PublicKeyTest, DifferentParametersNotEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters1 = Cecpq2Parameters::Create(
      *dem_parameters, "salt1", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters1, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters2 = Cecpq2Parameters::Create(
      *dem_parameters, "salt2", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters2, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters1)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> other_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters2)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Cecpq2PublicKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> other_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Cecpq2PublicKeyTest, DifferentX25519PublicKeyNotEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes1 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string x25519_public_key_bytes2 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes1)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> other_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes2)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Cecpq2PublicKeyTest, DifferentHrssPublicKeyNotEqual) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes1 =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);
  std::string hrss_public_key_bytes2 =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes1)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> other_public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes2)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(Cecpq2PublicKeyTest, CopyConstructor) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  Cecpq2PublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(Cecpq2PublicKeyTest, CopyAssignment) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes1 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string x25519_public_key_bytes2 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes1)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> copy =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes2)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());
  EXPECT_THAT(copy, Not(Eq(public_key)));

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(Cecpq2PublicKeyTest, MoveConstructor) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  Cecpq2PublicKey move(std::move(*public_key));

  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetX25519PublicKeyBytes(GetPartialKeyAccess()),
              x25519_public_key_bytes);
  EXPECT_THAT(move.GetHrssPublicKeyBytes(GetPartialKeyAccess()),
              hrss_public_key_bytes);
  EXPECT_THAT(move.GetIdRequirement(), Eq(absl::nullopt));
}

TEST(Cecpq2PublicKeyTest, MoveAssignment) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes1 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string x25519_public_key_bytes2 =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes1)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PublicKey> move =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes2)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());
  EXPECT_THAT(move, Not(Eq(public_key)));

  *move = std::move(*public_key);

  EXPECT_THAT(move->GetParameters(), Eq(*parameters));
  EXPECT_THAT(move->GetX25519PublicKeyBytes(GetPartialKeyAccess()),
              x25519_public_key_bytes1);
  EXPECT_THAT(move->GetHrssPublicKeyBytes(GetPartialKeyAccess()),
              hrss_public_key_bytes);
  EXPECT_THAT(move->GetIdRequirement(), Eq(absl::nullopt));
}

TEST(Cecpq2PublicKeyTest, Clone) {
  absl::StatusOr<XChaCha20Poly1305Parameters> dem_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(dem_parameters, IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters = Cecpq2Parameters::Create(
      *dem_parameters, "salt", Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  std::unique_ptr<Key> clone = public_key->Clone();

  EXPECT_THAT(*clone, Eq(*public_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
