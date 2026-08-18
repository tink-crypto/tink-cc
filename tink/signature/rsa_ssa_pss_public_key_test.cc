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

#include "tink/signature/rsa_ssa_pss_public_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  int modulus_size_in_bits;
  RsaSsaPssParameters::HashType hash_type;
  int salt_length_in_bytes;
  RsaSsaPssParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

// Returns static F4 public exponent (65537).
const BigInteger& GetF4() {
  static const absl::NoDestructor<BigInteger> f4(std::string("\x1\0\x1", 3));
  return *f4;
}

// Returns static 2048-bit RSA SSA PSS public key from
// CreateRsaSsaPssTestVectors().
const RsaSsaPssPublicKey& Get2048BitPublicKey() {
  const RsaSsaPssPublicKey* key = dynamic_cast<const RsaSsaPssPublicKey*>(
      &internal::GetRsaSsaPssTestVector(2048,
                                        RsaSsaPssParameters::HashType::kSha256,
                                        RsaSsaPssParameters::Variant::kNoPrefix)
           .signature_private_key->GetPublicKey());
  ABSL_CHECK_NE(key, nullptr);
  return *key;
}

using RsaSsaPssPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssPublicKeyTestSuite, RsaSsaPssPublicKeyTest,
    Values(
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha256,
                 /*salt_length_in_bytes*/ 0,
                 RsaSsaPssParameters::Variant::kTink,
                 /*id_requirement=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha256,
                 /*salt_length_in_bytes*/ 32,
                 RsaSsaPssParameters::Variant::kCrunchy,
                 /*id_requirement=*/0x01030005,
                 /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha384,
                 /*salt_length_in_bytes*/ 48,
                 RsaSsaPssParameters::Variant::kLegacy,
                 /*id_requirement=*/0x07080910,
                 /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
        TestCase{/*modulus_size=*/2048, RsaSsaPssParameters::HashType::kSha512,
                 /*salt_length_in_bytes*/ 64,
                 RsaSsaPssParameters::Variant::kNoPrefix,
                 /*id_requirement=*/std::nullopt,
                 /*output_prefix=*/""}));

TEST_P(RsaSsaPssPublicKeyTest, CreatePublicKeySucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(GetF4())
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetModulus(GetPartialKeyAccess()), Eq(modulus));
}

TEST(RsaSsaPssPublicKeyTest, CreateWithNonMatchingModulusSizeFails) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Ed25519PublicKeyTest, CreateKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<RsaSsaPssParameters> no_prefix_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_parameters, IsOk());

  absl::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  EXPECT_THAT(
      RsaSsaPssPublicKey::Create(*no_prefix_parameters, modulus,
                                 /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));

  EXPECT_THAT(RsaSsaPssPublicKey::Create(*tink_parameters, modulus,
                                         /*id_requirement=*/std::nullopt,
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPssPublicKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(GetF4())
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus, test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*parameters, modulus, test_case.id_requirement,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentParametersNotEqual) {
  absl::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  absl::StatusOr<RsaSsaPssParameters> crunchy_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*crunchy_parameters, modulus,
                                 /*id_requirement=*/0x02030400,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentModulusNotEqual) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string other_modulus_bytes = test::HexDecodeOrDie(
      "00c684aef47bc201764a663acdf22e67140410b3d201533b6ccaebf86eda3d81a1230a1c"
      "c5ce2c9e4e102d107f2418d9386f1d3734eb922629b4e7ef464f79fcac53744702a147c1"
      "ef8dafc8eb366284d3419d98e8cf176ccb7f65bada528c222956900e1ec0c2f21e83e3ee"
      "30d946a6aa267e01a28b9c1833b035a881ad1865dfd2a451086a46f38ed137237c5fe368"
      "261e3a46712399f3c56ac6fbde33682ba98c95e435e1dec2d5b9d681ade372622c2dbdbe"
      "47b419b4ba23a5defc3f792d4d8373cc27cf707dd2f3603363a0ffe643dcfda79758ad1a"
      "c53d46f1a5ec25df1ddd94780a8f51f88ffb32337f05395dec93267802db95243f1b62cc"
      "3dd8118d2d");

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  BigInteger other_modulus(other_modulus_bytes);

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*parameters, other_modulus,
                                 /*id_requirement=*/std::nullopt,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, DifferentIdRequirementNotEqual) {
  absl::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  absl::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*tink_parameters, modulus,
                                 /*id_requirement=*/0x01020304,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(RsaSsaPssPublicKeyTest, PaddedWithZerosModulusEqual) {
  absl::StatusOr<RsaSsaPssParameters> tink_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());
  BigInteger padded_with_zeros_modulus(std::string("\0\0\0", 3) +
                                       std::string(modulus.GetValue()));
  ASSERT_THAT(modulus, Eq(padded_with_zeros_modulus));

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *tink_parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> other_public_key =
      RsaSsaPssPublicKey::Create(*tink_parameters, padded_with_zeros_modulus,
                                 /*id_requirement=*/0x02030400,
                                 GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(RsaSsaPssPublicKeyTest, Clone) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key
  std::unique_ptr<Key> cloned_key = public_key->Clone();
  ASSERT_THAT(*cloned_key, Eq(*public_key));
}

TEST(RsaSsaPssPublicKeyTest, CopyConstructor) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RsaSsaPssPublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(RsaSsaPssPublicKeyTest, CopyAssignment) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> copy = RsaSsaPssPublicKey::Create(
      *other_parameters, modulus,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(RsaSsaPssPublicKeyTest, MoveConstructor) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RsaSsaPssPublicKey expected(*public_key);
  RsaSsaPssPublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(RsaSsaPssPublicKeyTest, MoveAssignment) {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssParameters> other_parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(GetF4())
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSaltLengthInBytes(64)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  BigInteger modulus = Get2048BitPublicKey().GetModulus(GetPartialKeyAccess());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, modulus,
      /*id_requirement=*/0x02030400, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> moved = RsaSsaPssPublicKey::Create(
      *other_parameters, modulus,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  RsaSsaPssPublicKey expected(*public_key);
  *moved = *public_key;

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
