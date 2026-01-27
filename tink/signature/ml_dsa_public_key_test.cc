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
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/mldsa.h"
#include "tink/internal/secret_buffer.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ml_dsa_parameters.h"
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

using MlDsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    MlDsaPublicKeyTestSuite, MlDsaPublicKeyTest,
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

using MlDsaPublicKeyTest = TestWithParam<TestCase>;

std::string GeneratePublicKey(MlDsaParameters::Instance instance) {
  if (instance == MlDsaParameters::Instance::kMlDsa65) {
    std::string public_key_bytes;
    public_key_bytes.resize(MLDSA65_PUBLIC_KEY_BYTES);
    internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
    auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA65_private_key>();

    ABSL_CHECK_EQ(1, MLDSA65_generate_key(
                         reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                         private_seed_bytes.data(), bssl_private_key.get()));

    return public_key_bytes;
  } else if (instance == MlDsaParameters::Instance::kMlDsa87) {
    std::string public_key_bytes;
    public_key_bytes.resize(MLDSA87_PUBLIC_KEY_BYTES);
    internal::SecretBuffer private_seed_bytes(MLDSA_SEED_BYTES);
    auto bssl_private_key = util::MakeSecretUniquePtr<MLDSA87_private_key>();

    ABSL_CHECK_EQ(1, MLDSA87_generate_key(
                         reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
                         private_seed_bytes.data(), bssl_private_key.get()));

    return public_key_bytes;
  } else {
    ABSL_LOG(FATAL) << "Unsupported ML-DSA instance";
  }
}

int PublicKeyBytes(MlDsaParameters::Instance instance) {
  switch (instance) {
    case MlDsaParameters::Instance::kMlDsa65:
      return MLDSA65_PUBLIC_KEY_BYTES;
    case MlDsaParameters::Instance::kMlDsa87:
      return MLDSA87_PUBLIC_KEY_BYTES;
    default:
      ABSL_LOG(FATAL) << "Unsupported ML-DSA instance";
  }
}

TEST_P(MlDsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);
  absl::StatusOr<MlDsaPublicKey> public_key =
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

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);
  EXPECT_THAT(
      MlDsaPublicKey::Create(
          *parameters,
          public_key_bytes.substr(0, PublicKeyBytes(test_case.instance) - 1),
          test_case.id_requirement, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA public key size. Only ",
                                      PublicKeyBytes(test_case.instance),
                                      "-byte keys are currently supported"))));

  public_key_bytes.push_back(0);
  EXPECT_THAT(
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat("Invalid ML-DSA public key size. Only ",
                                      PublicKeyBytes(test_case.instance),
                                      "-byte keys are currently supported"))));
}

TEST_P(MlDsaPublicKeyTest, CreateKeyWithNoIdRequirementWithTinkParamsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);
  EXPECT_THAT(MlDsaPublicKey::Create(*parameters, public_key_bytes,
                                     /*id_requirement=*/absl::nullopt,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST_P(MlDsaPublicKeyTest, CreateKeyWithIdRequirementWithNoPrefixParamsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);
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

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPublicKey> other_public_key =
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

  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(test_case.instance, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes1 = GeneratePublicKey(test_case.instance);
  std::string public_key_bytes2 = GeneratePublicKey(test_case.instance);

  absl::StatusOr<MlDsaPublicKey> public_key1 =
      MlDsaPublicKey::Create(*parameters, public_key_bytes1,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key2 =
      MlDsaPublicKey::Create(*parameters, public_key_bytes2,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  EXPECT_TRUE(*public_key1 != *public_key2);
  EXPECT_TRUE(*public_key2 != *public_key1);
  EXPECT_FALSE(*public_key1 == *public_key2);
  EXPECT_FALSE(*public_key2 == *public_key1);
}

TEST_P(MlDsaPublicKeyTest, DifferentIdRequirementNotEqual) {
  TestCase test_case = GetParam();

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      test_case.instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes = GeneratePublicKey(test_case.instance);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPublicKey> other_public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(MlDsaPublicKeyTest, Clone) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa65);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = public_key->Clone();

  EXPECT_THAT(*cloned_key, Eq(*public_key));
}

TEST(MlDsaPublicKeyTest, CopyConstructor) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa65);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  MlDsaPublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(MlDsaPublicKeyTest, CopyAssignment) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa65);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  std::string other_public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa87);

  absl::StatusOr<MlDsaPublicKey> copy = MlDsaPublicKey::Create(
      *other_parameters, other_public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(MlDsaPublicKeyTest, MoveConstructor) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa65);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  MlDsaPublicKey expected(*public_key);
  MlDsaPublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(MlDsaPublicKeyTest, MoveAssignment) {
  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa65);

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaParameters> other_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(other_parameters, IsOk());

  std::string other_public_key_bytes =
      GeneratePublicKey(MlDsaParameters::Instance::kMlDsa87);

  absl::StatusOr<MlDsaPublicKey> moved = MlDsaPublicKey::Create(
      *other_parameters, other_public_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  MlDsaPublicKey expected(*public_key);
  *moved = std::move(*public_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
