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

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "tink/internal/fips_utils.h"  // IWYU pragma: keep
#ifndef TINK_USE_ONLY_FIPS
#include "openssl/mldsa.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/subtle/random.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

#ifdef TINK_USE_ONLY_FIPS
using MlDsaPrivateKeyTest = TestWithParam<MlDsaParameters::Instance>;

INSTANTIATE_TEST_SUITE_P(MlDsaPrivateKeyTestSuite, MlDsaPrivateKeyTest,
                         testing::Values(MlDsaParameters::Instance::kMlDsa44,
                                         MlDsaParameters::Instance::kMlDsa65,
                                         MlDsaParameters::Instance::kMlDsa87));

TEST_P(MlDsaPrivateKeyTest, CreateFipsFails) {
  MlDsaParameters::Instance instance = GetParam();
  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  int pub_key_bytes = instance == MlDsaParameters::Instance::kMlDsa44   ? 1312
                      : instance == MlDsaParameters::Instance::kMlDsa65 ? 1952
                                                                        : 2592;
  std::string public_key_bytes = subtle::Random::GetRandomBytes(pub_key_bytes);
  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_seed_bytes = RestrictedData(32);
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*public_key, private_seed_bytes,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kUnimplemented,
          HasSubstr("ML-DSA is only supported in non-FIPS BoringSSL builds.")));
}

TEST_P(MlDsaPrivateKeyTest, CreateFromSeedFipsFails) {
  MlDsaParameters::Instance instance = GetParam();
  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData private_seed_bytes = RestrictedData(32);
  EXPECT_THAT(
      MlDsaPrivateKey::Create(*parameters, private_seed_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kUnimplemented,
          HasSubstr("ML-DSA is only supported in non-FIPS BoringSSL builds.")));
}
#else
using MlDsaPrivateKeyTest = TestWithParam<internal::SignatureTestVector>;

INSTANTIATE_TEST_SUITE_P(MlDsaPrivateKeyTestSuite, MlDsaPrivateKeyTest,
                         ValuesIn(internal::CreateMlDsaTestVectors()));
TEST_P(MlDsaPrivateKeyTest, CreateSucceeds) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      test_private_key->GetPublicKey(),
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetPublicKey().GetParameters(),
              Eq(test_private_key->GetPublicKey().GetParameters()));
  EXPECT_THAT(private_key->GetIdRequirement(),
              Eq(test_private_key->GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(),
              Eq(test_private_key->GetPublicKey()));
  EXPECT_THAT(private_key->GetOutputPrefix(),
              Eq(test_private_key->GetOutputPrefix()));
  EXPECT_THAT(private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
              Eq(test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())));
}

TEST_P(MlDsaPrivateKeyTest, CreateFromSeedSucceeds) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      test_private_key->GetPublicKey().GetParameters(),
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
      test_private_key->GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetPublicKey().GetParameters(),
              Eq(test_private_key->GetPublicKey().GetParameters()));
  EXPECT_THAT(private_key->GetIdRequirement(),
              Eq(test_private_key->GetIdRequirement()));
  EXPECT_THAT(private_key->GetPublicKey(),
              Eq(test_private_key->GetPublicKey()));
  EXPECT_THAT(private_key->GetOutputPrefix(),
              Eq(test_private_key->GetOutputPrefix()));
  EXPECT_THAT(private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
              Eq(test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())));
}

TEST_P(MlDsaPrivateKeyTest, CreateFromSeedWithInvalidPrivateKeyLengthFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  RestrictedData private_seed_bytes = RestrictedData(
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get())
          .substr(MLDSA_SEED_BYTES - 1),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(
          test_private_key->GetPublicKey().GetParameters(), private_seed_bytes,
          test_private_key->GetIdRequirement(), GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));

  std::string longer_private_seed_bytes(
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()));
  longer_private_seed_bytes.push_back(0);
  private_seed_bytes =
      RestrictedData(longer_private_seed_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(
          test_private_key->GetPublicKey().GetParameters(), private_seed_bytes,
          test_private_key->GetIdRequirement(), GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));
}

TEST_P(MlDsaPrivateKeyTest, CreateFromSeedWithMismatchedIdRequirementFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  if (test_private_key->GetPublicKey().GetParameters().HasIdRequirement()) {
    EXPECT_THAT(
        MlDsaPrivateKey::Create(
            test_private_key->GetPublicKey().GetParameters(),
            test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
            /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(
        MlDsaPrivateKey::Create(
            test_private_key->GetPublicKey().GetParameters(),
            test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess()),
            /*id_requirement=*/123, GetPartialKeyAccess())
            .status(),
        StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_P(MlDsaPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  RestrictedData private_seed_bytes = RestrictedData(
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get())
          .substr(MLDSA_SEED_BYTES - 1),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(test_private_key->GetPublicKey(),
                              private_seed_bytes, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));

  std::string longer_private_seed_bytes(
      test_private_key->GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()));
  longer_private_seed_bytes.push_back(0);
  private_seed_bytes =
      RestrictedData(longer_private_seed_bytes, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      MlDsaPrivateKey::Create(test_private_key->GetPublicKey(),
                              private_seed_bytes, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(absl::StrCat(
                   "Invalid ML-DSA private seed size. The seed must be ",
                   MLDSA_SEED_BYTES, " bytes."))));
}

TEST_P(MlDsaPrivateKeyTest, CreateWithMismatchedKeysFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  RestrictedData mismatched_seed =
      RestrictedData(subtle::Random::GetRandomBytes(MLDSA_SEED_BYTES),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      MlDsaPrivateKey::Create(test_private_key->GetPublicKey(), mismatched_seed,
                              GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("ML-DSA public key doesn't match the private key")));
}

TEST_P(MlDsaPrivateKeyTest, KeyEquals) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  MlDsaPrivateKey copy = *test_private_key;

  EXPECT_TRUE(*test_private_key == copy);
  EXPECT_TRUE(copy == *test_private_key);
  EXPECT_FALSE(*test_private_key != copy);
  EXPECT_FALSE(copy != *test_private_key);
}

TEST_P(MlDsaPrivateKeyTest, DifferentKeyBytesNotEqual) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const MlDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      test_private_key->GetPublicKey().GetParameters(),
      RestrictedData(subtle::Random::GetRandomBytes(MLDSA_SEED_BYTES),
                     InsecureSecretKeyAccess::Get()),
      test_private_key->GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*test_private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *test_private_key);
  EXPECT_FALSE(*test_private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *test_private_key);
}

TEST(MlDsaPrivateKeyTest, DifferentIdRequirementNotEqual) {
  const auto* private_key1 = static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());

  absl::StatusOr<MlDsaPublicKey> public_key456 = MlDsaPublicKey::Create(
      private_key1->GetPublicKey().GetParameters(),
      private_key1->GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()),
      /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  absl::StatusOr<MlDsaPrivateKey> other_private_key = MlDsaPrivateKey::Create(
      *public_key456, private_key1->GetPrivateSeedBytes(GetPartialKeyAccess()),
      GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key1 != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key1);
  EXPECT_FALSE(*private_key1 == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key1);
}

TEST(MlDsaPrivateKeyTest, Clone) {
  const auto* private_key = static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  EXPECT_THAT(*cloned_key, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, CopyConstructor) {
  const auto* private_key = static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());

  MlDsaPrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, CopyAssignment) {
  const auto* private_key = static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());
  const auto* other_private_key = static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa87,
                                   MlDsaParameters::Variant::kNoPrefix)
          .signature_private_key.get());

  MlDsaPrivateKey copy = *other_private_key;
  copy = *private_key;

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(MlDsaPrivateKeyTest, MoveConstructor) {
  MlDsaPrivateKey private_key = *static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());

  MlDsaPrivateKey expected = private_key;
  MlDsaPrivateKey moved(std::move(private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(MlDsaPrivateKeyTest, MoveAssignment) {
  MlDsaPrivateKey private_key = *static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa65,
                                   MlDsaParameters::Variant::kTink)
          .signature_private_key.get());
  MlDsaPrivateKey other_private_key = *static_cast<const MlDsaPrivateKey*>(
      internal::GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa87,
                                   MlDsaParameters::Variant::kNoPrefix)
          .signature_private_key.get());

  MlDsaPrivateKey expected = private_key;
  other_private_key = std::move(private_key);

  EXPECT_THAT(other_private_key, Eq(expected));
}
#endif  // TINK_USE_ONLY_FIPS

}  // namespace
}  // namespace tink
}  // namespace crypto
