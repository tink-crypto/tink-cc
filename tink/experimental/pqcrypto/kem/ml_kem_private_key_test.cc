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

#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mlkem.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/secret_buffer.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  MlKemParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using MlKemPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlKemPrivateKeyTestSuite, MlKemPrivateKeyTest,
    Values(TestCase{MlKemParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlKemParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)}));

struct KeyPair {
  std::string public_key_bytes;
  RestrictedData private_seed_bytes;
};

absl::StatusOr<KeyPair> GenerateKeyPair() {
  std::string public_key_bytes;
  public_key_bytes.resize(MLKEM768_PUBLIC_KEY_BYTES);
  internal::SecretBuffer private_seed_bytes(MLKEM_SEED_BYTES);
  auto bssl_private_key = util::MakeSecretUniquePtr<MLKEM768_private_key>();

  MLKEM768_generate_key(reinterpret_cast<uint8_t *>(&public_key_bytes[0]),
                        private_seed_bytes.data(), bssl_private_key.get());

  return KeyPair{
      public_key_bytes,
      RestrictedData(
          util::internal::AsSecretData(std::move(private_seed_bytes)),
          InsecureSecretKeyAccess::Get()),
  };
}

TEST_P(MlKemPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
              Eq(key_pair->private_seed_bytes));
}

TEST_P(MlKemPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed_bytes = RestrictedData(
      key_pair->private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get())
          .substr(MLKEM_SEED_BYTES - 1),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(MlKemPrivateKey::Create(*public_key, private_seed_bytes,
                                      GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr(absl::StrCat(
                           "Invalid ML-KEM private seed. The seed must be ",
                           MLKEM_SEED_BYTES, " bytes."))));

  std::string longer_private_seed_bytes(
      key_pair->private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get()));
  longer_private_seed_bytes.push_back(0);
  private_seed_bytes =
      RestrictedData(longer_private_seed_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(MlKemPrivateKey::Create(*public_key, private_seed_bytes,
                                      GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr(absl::StrCat(
                           "Invalid ML-KEM private seed. The seed must be ",
                           MLKEM_SEED_BYTES, " bytes."))));
}

TEST_P(MlKemPrivateKeyTest, CreateWithMismatchedPublicKeyFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair1 = GenerateKeyPair();
  ASSERT_THAT(key_pair1, IsOk());
  absl::StatusOr<KeyPair> key_pair2 = GenerateKeyPair();
  ASSERT_THAT(key_pair2, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key1 =
      MlKemPublicKey::Create(*parameters, key_pair1->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  EXPECT_THAT(
      MlKemPrivateKey::Create(*public_key1, key_pair2->private_seed_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ML-KEM public key doesn't match the private key.")));
}

TEST_P(MlKemPrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlKemPrivateKey> other_private_key = MlKemPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST_P(MlKemPrivateKeyTest, DifferentKeyBytesNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair1 = GenerateKeyPair();
  ASSERT_THAT(key_pair1, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key1 =
      MlKemPublicKey::Create(*parameters, key_pair1->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key1 = MlKemPrivateKey::Create(
      *public_key1, key_pair1->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<KeyPair> key_pair2 = GenerateKeyPair();
  ASSERT_THAT(key_pair2, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key2 =
      MlKemPublicKey::Create(*parameters, key_pair2->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key2 = MlKemPrivateKey::Create(
      *public_key2, key_pair2->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST_P(MlKemPrivateKeyTest, DifferentIdRequirementNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlKemParameters> parameters =
      MlKemParameters::Create(/*key_size=*/768, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key123 =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key456 =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key123, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlKemPrivateKey> other_private_key = MlKemPrivateKey::Create(
      *public_key456, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(MlKemPrivateKeyTest, Clone) {
  absl::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlKemPublicKey> public_key =
      MlKemPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
