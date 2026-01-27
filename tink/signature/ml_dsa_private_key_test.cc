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

#include "tink/signature/ml_dsa_private_key.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/secret_buffer.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/secret_data.h"
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
  MlDsaParameters::Instance instance;
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using MlDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrivateKeyTestSuite, MlDsaPrivateKeyTest,
    Values(TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa65,
                    MlDsaParameters::Variant::kNoPrefix, absl::nullopt, ""},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{MlDsaParameters::Instance::kMlDsa87,
                    MlDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

struct KeyPair {
  std::string public_key_bytes;
  RestrictedData private_seed_bytes;
};

absl::StatusOr<KeyPair> GenerateKeyPair(MlDsaParameters::Instance instance) {
  if (instance == MlDsaParameters::Instance::kMlDsa65) {
    std::string public_key_bytes;
    public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
    internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
    auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();

    ABSL_CHECK_EQ(1, MLDSA65_generate_key(
                         reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                         private_seed_bytes.data(), bssl_private_key.get()));

    return KeyPair{
        public_key_bytes,
        RestrictedData(
            util::internal::AsSecretData(std::move(private_seed_bytes)),
            InsecureSecretKeyAccess::Get()),
    };
  } else if (instance == MlDsaParameters::Instance::kMlDsa87) {
    std::string public_key_bytes;
    public_key_bytes.resize(MLDSA87_PUBLIC_KEY_BYTES);
    internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
    auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();

    ABSL_CHECK_EQ(1, MLDSA87_generate_key(
                         reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                         private_seed_bytes.data(), bssl_private_key.get()));

    return KeyPair{
        public_key_bytes,
        RestrictedData(
            util::internal::AsSecretData(std::move(private_seed_bytes)),
            InsecureSecretKeyAccess::Get()),
    };
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("Unsupported instance: ", instance));
  }
}

TEST_P(MlDsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
              Eq(key_pair->private_seed_bytes));
}

TEST_P(MlDsaPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed_bytes = RestrictedData(
      key_pair->private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get())
          .substr(MLDSA_SEED_BYTES - 1),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key, private_seed_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));

  std::string longer_private_seed_bytes(
      key_pair->private_seed_bytes.GetSecret(InsecureSecretKeyAccess::Get()));
  longer_private_seed_bytes.push_back(0);
  private_seed_bytes =
      RestrictedData(longer_private_seed_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key, private_seed_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));
}

TEST_P(MlDsaPrivateKeyTest, CreateWithMismatchedKeysFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair1 = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair1, IsOk());
  absl::StatusOr<KeyPair> key_pair2 = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair2, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key1 =
      MlDsaPublicKey::Create(*parameters, key_pair1->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key1, key_pair2->private_seed_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ML-DSA public key doesn't match the private key")));
}

TEST_P(MlDsaPrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST_P(MlDsaPrivateKeyTest, DifferentKeyBytesNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair1 = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair1, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key1 =
      MlDsaPublicKey::Create(*parameters, key_pair1->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key1 = MlDsaPrivateKey::Create(
      *public_key1, key_pair1->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<KeyPair> key_pair2 = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair2, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key2 =
      MlDsaPublicKey::Create(*parameters, key_pair2->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key2 = MlDsaPrivateKey::Create(
      *public_key2, key_pair2->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST_P(MlDsaPrivateKeyTest, DifferentIdRequirementNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.instance);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key123 =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key456 =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key123, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      *public_key456, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

TEST(MlDsaPrivateKeyTest, Clone) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa65);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  EXPECT_THAT(*cloned_key, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, CopyConstructor) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa65);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  MlDsaPrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, CopyAssignment) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa65);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<KeyPair> other_key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa87);
  ASSERT_THAT(other_key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> other_public_key = MlDsaPublicKey::Create(
      *other_parameters, other_key_pair->public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> copy = MlDsaPrivateKey::Create(
      *other_public_key, other_key_pair->private_seed_bytes,
      GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, MoveConstructor) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa65);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  MlDsaPrivateKey expected(*private_key);
  MlDsaPrivateKey moved(std::move(*private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(MlDsaPrivateKeyTest, MoveAssignment) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa65);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_seed_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<KeyPair> other_key_pair =
      GenerateKeyPair(MlDsaParameters::Instance::kMlDsa87);
  ASSERT_THAT(other_key_pair, IsOk());

  absl::StatusOr<MlDsaPublicKey> other_public_key = MlDsaPublicKey::Create(
      *other_parameters, other_key_pair->public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> moved = MlDsaPrivateKey::Create(
      *other_public_key, other_key_pair->private_seed_bytes,
      GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  MlDsaPrivateKey expected(*private_key);
  *moved = std::move(*private_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
