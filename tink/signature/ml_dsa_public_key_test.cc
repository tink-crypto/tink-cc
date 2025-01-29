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

#include "tink/signature/ml_dsa_public_key.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/internal/secret_buffer.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ml_dsa_parameters.h"
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
  MlDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using MlDsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPublicKeyTestSuite, MlDsaPublicKeyTest,
    Values(TestCase{MlDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{MlDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

using MlDsaPublicKeyTest = TestWithParam<TestCase>;

std::string GeneratePublicKey() {
  std::string public_key_bytes;
  public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
  internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
  auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();

  CHECK_EQ(1, MLDSA65_generate_key(
                  reinterpret_cast<uint8_t *>(&public_key_bytes[0]),
                  private_seed_bytes.data(), bssl_private_key.get()));

  return public_key_bytes;
}

TEST_P(MlDsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();
  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicKeyBytes(GetPartialKeyAccess()),
              Eq(public_key_bytes));
}

TEST_P(MlDsaPublicKeyTest, CreateWithInvalidPublicKeyLengthFails) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();
  EXPECT_THAT(
      MlDsaPublicKey::Create(
          *parameters, public_key_bytes.substr(0, MLDSA65_PUBLIC_KEY_BYTES - 1),
          test_case.id_requirement, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA public key size. Only ",
                                      MLDSA65_PUBLIC_KEY_BYTES,
                                      "-byte keys are currently supported."))));

  public_key_bytes.push_back(0);
  EXPECT_THAT(
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA public key size. Only ",
                                      MLDSA65_PUBLIC_KEY_BYTES,
                                      "-byte keys are currently supported."))));
}

TEST(MlDsaPublicKeyTest, CreateKeyWithNoIdRequirementWithTinkParamsFails) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();
  EXPECT_THAT(MlDsaPublicKey::Create(*parameters, public_key_bytes,
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST(MlDsaPublicKeyTest, CreateKeyWithIdRequirementWithNoPrefixParamsFails) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();
  EXPECT_THAT(
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key with ID requirement with parameters without ID "
                         "requirement")));
}

TEST_P(MlDsaPublicKeyTest, PublicKeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPublicKey> other_public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST_P(MlDsaPublicKeyTest, DifferentPublicKeyBytesNotEqual) {
  TestCase test_case = GetParam();

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes1 = GeneratePublicKey();
  std::string public_key_bytes2 = GeneratePublicKey();

  util::StatusOr<MlDsaPublicKey> public_key1 =
      MlDsaPublicKey::Create(*parameters, public_key_bytes1,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key2 =
      MlDsaPublicKey::Create(*parameters, public_key_bytes2,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  EXPECT_TRUE(*public_key1 != *public_key2);
  EXPECT_TRUE(*public_key2 != *public_key1);
  EXPECT_FALSE(*public_key1 == *public_key2);
  EXPECT_FALSE(*public_key2 == *public_key1);
}

TEST(MlDsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPublicKey> other_public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(MlDsaPublicKeyTest, Clone) {
  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey();

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = public_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*public_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
