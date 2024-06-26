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

#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/base.h"
#include "openssl/boringssl/src/include/openssl/base.h"
#include "openssl/bytestring.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_DILITHIUM
#include "openssl/experimental/dilithium.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
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
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using MlDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrivateKeyTestSuite, MlDsaPrivateKeyTest,
    Values(TestCase{MlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{MlDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

struct KeyPair {
  std::string public_key_bytes;
  RestrictedData private_key_bytes;
};

util::StatusOr<KeyPair> GenerateKeyPair() {
  std::string public_key_bytes;
  public_key_bytes.resize(DILITHIUM_PUBLIC_KEY_BYTES);
  auto bssl_private_key = util::MakeSecretUniquePtr<DILITHIUM_private_key>();

  DILITHIUM_generate_key(reinterpret_cast<uint8_t *>(&public_key_bytes[0]),
                         bssl_private_key.get());

  CBB cbb;
  size_t size;
  util::SecretData private_key_bytes(DILITHIUM_PRIVATE_KEY_BYTES);
  if (!CBB_init_fixed(&cbb, private_key_bytes.data(),
                      DILITHIUM_PRIVATE_KEY_BYTES) ||
      !DILITHIUM_marshal_private_key(&cbb, bssl_private_key.get()) ||
      !CBB_finish(&cbb, nullptr, &size) ||
      size != DILITHIUM_PRIVATE_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to serialize ML-DSA private key");
  }

  return KeyPair{
      public_key_bytes,
      RestrictedData(std::move(private_key_bytes),
                     InsecureSecretKeyAccess::Get()),
  };
}

TEST_P(MlDsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(key_pair->private_key_bytes));
}

TEST_P(MlDsaPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      key_pair->private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get())
          .substr(DILITHIUM_PRIVATE_KEY_BYTES - 1),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key, private_key_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA private key size. Only ",
                                      DILITHIUM_PRIVATE_KEY_BYTES,
                                      "-byte keys are currently supported."))));

  std::string longer_private_key_bytes(
      key_pair->private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get()));
  longer_private_key_bytes.push_back(0);
  private_key_bytes =
      RestrictedData(longer_private_key_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key, private_key_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA private key size. Only ",
                                      DILITHIUM_PRIVATE_KEY_BYTES,
                                      "-byte keys are currently supported."))));
}

TEST_P(MlDsaPrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      *public_key, key_pair->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST_P(MlDsaPrivateKeyTest, DifferentKeyBytesNotEqual) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair1 = GenerateKeyPair();
  ASSERT_THAT(key_pair1, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key1 =
      MlDsaPublicKey::Create(*parameters, key_pair1->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key1 = MlDsaPrivateKey::Create(
      *public_key1, key_pair1->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  util::StatusOr<KeyPair> key_pair2 = GenerateKeyPair();
  ASSERT_THAT(key_pair2, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key2 =
      MlDsaPublicKey::Create(*parameters, key_pair2->public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key2 = MlDsaPrivateKey::Create(
      *public_key2, key_pair2->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST_P(MlDsaPrivateKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeyPair> key_pair = GenerateKeyPair();
  ASSERT_THAT(key_pair, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key123 =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key456 =
      MlDsaPublicKey::Create(*parameters, key_pair->public_key_bytes,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key123, key_pair->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      *public_key456, key_pair->private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
