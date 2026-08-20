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

#include "tink/signature/slh_dsa_private_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"  // IWYU pragma: keep
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/slh_dsa_parameter_set.h"
#include "tink/signature/internal/slh_dsa_sign_boringssl.h"
#include "tink/signature/internal/slh_dsa_verify_boringssl.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/internal/testing/slh_dsa_test_vectors.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_public_key.h"
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
struct TestCase {
  SlhDsaParameters::HashType hash_type;
  int private_key_size_in_bytes;
  int public_key_size_in_bytes;
  SlhDsaParameters::SignatureType signature_type;
  SlhDsaParameters::Variant variant;
};

using SlhDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    SlhDsaPrivateKeyTestSuite, SlhDsaPrivateKeyTest,
    testing::Values(TestCase{SlhDsaParameters::HashType::kSha2,
                             /*private_key_size_in_bytes=*/64,
                             /*public_key_size_in_bytes=*/32,
                             SlhDsaParameters::SignatureType::kSmallSignature,
                             SlhDsaParameters::Variant::kTink},
                    TestCase{SlhDsaParameters::HashType::kShake,
                             /*private_key_size_in_bytes=*/128,
                             /*public_key_size_in_bytes=*/64,
                             SlhDsaParameters::SignatureType::kFastSigning,
                             SlhDsaParameters::Variant::kTink}));

TEST_P(SlhDsaPrivateKeyTest, CreateFipsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      test_case.hash_type, test_case.private_key_size_in_bytes,
      test_case.signature_type, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes =
      subtle::Random::GetRandomBytes(test_case.public_key_size_in_bytes);
  absl::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(test_case.private_key_size_in_bytes),
      InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*public_key, private_key_bytes,
                               GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kUnimplemented,
               HasSubstr(
                   "SLH-DSA is only supported in non-FIPS BoringSSL builds.")));
}

TEST_P(SlhDsaPrivateKeyTest, CreateFromSeedFipsFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      test_case.hash_type, test_case.private_key_size_in_bytes,
      test_case.signature_type, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(*parameters);
  ASSERT_THAT(parameter_set, IsOk());

  RestrictedData seed =
      RestrictedData(subtle::Random::GetRandomBytes(
                         parameter_set->GetPrivateSeedSizeInBytes()),
                     InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      SlhDsaPrivateKey::CreateFromSeed(*parameters, seed,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kUnimplemented,
               HasSubstr(
                   "SLH-DSA is only supported in non-FIPS BoringSSL builds.")));
}
#else
using SlhDsaPrivateKeyTest = TestWithParam<internal::SignatureTestVector>;

INSTANTIATE_TEST_SUITE_P(SlhDsaPrivateKeyTestSuite, SlhDsaPrivateKeyTest,
                         ValuesIn(internal::CreateSlhDsaTestVectors()));
TEST_P(SlhDsaPrivateKeyTest, CreateSucceeds) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      test_private_key->GetPublicKey(),
      test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
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
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())));
}

TEST_P(SlhDsaPrivateKeyTest, CreateFromParametersSucceeds) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      test_private_key->GetPublicKey().GetParameters(),
      test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
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
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())));
}

TEST_P(SlhDsaPrivateKeyTest, CreateFromSeedSucceeds) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(
          test_private_key->GetPublicKey().GetParameters());
  ASSERT_THAT(parameter_set, IsOk());

  RestrictedData seed =
      RestrictedData(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())
                         .GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, parameter_set->GetPrivateSeedSizeInBytes()),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<SlhDsaPrivateKey> private_key =
      SlhDsaPrivateKey::CreateFromSeed(
          test_private_key->GetPublicKey().GetParameters(), seed,
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
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())));
}

TEST_P(SlhDsaPrivateKeyTest, CreateFromSeedGeneratesConsistentKeyPair) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(
          test_private_key->GetPublicKey().GetParameters());
  ASSERT_THAT(parameter_set, IsOk());

  RestrictedData seed =
      RestrictedData(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())
                         .GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, parameter_set->GetPrivateSeedSizeInBytes()),
                     InsecureSecretKeyAccess::Get());

  absl::StatusOr<SlhDsaPrivateKey> private_key =
      SlhDsaPrivateKey::CreateFromSeed(
          test_private_key->GetPublicKey().GetParameters(), seed,
          test_private_key->GetIdRequirement(), GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign> > signer =
      internal::NewSlhDsaSignBoringSsl(*private_key);
  ASSERT_THAT(signer, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify> > verifier =
      internal::NewSlhDsaVerifyBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(verifier, IsOk());

  std::string message = "Self-verify test message";
  absl::StatusOr<std::string> signature = (*signer)->Sign(message);
  ASSERT_THAT(signature, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, message), IsOk());
}

TEST(SlhDsaPrivateKeyTest, CreateFromSeedWithInvalidSeedLengthFails) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  // General invalid seed length (47 bytes, not 48, 72, or 96 bytes)
  RestrictedData invalid_seed(47);
  EXPECT_THAT(
      SlhDsaPrivateKey::CreateFromSeed(*parameters, invalid_seed,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess())
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "SLH-DSA private seed length must be 48, 72, or 96 bytes.")));

  // Mismatched seed size (96 bytes, but parameters expect 48 bytes)
  RestrictedData mismatched_seed(96);
  EXPECT_THAT(
      SlhDsaPrivateKey::CreateFromSeed(*parameters, mismatched_seed,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Private key size does not match parameters")));
}

TEST_P(SlhDsaPrivateKeyTest, CreateFromSeedWithMismatchedIdRequirementFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  absl::StatusOr<internal::SlhDsaParameterSet> parameter_set =
      internal::GetSlhDsaParameterSet(
          test_private_key->GetPublicKey().GetParameters());
  ASSERT_THAT(parameter_set, IsOk());

  RestrictedData seed =
      RestrictedData(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())
                         .GetSecret(InsecureSecretKeyAccess::Get())
                         .substr(0, parameter_set->GetPrivateSeedSizeInBytes()),
                     InsecureSecretKeyAccess::Get());

  if (test_private_key->GetParameters().HasIdRequirement()) {
    EXPECT_THAT(SlhDsaPrivateKey::CreateFromSeed(
                    test_private_key->GetPublicKey().GetParameters(), seed,
                    /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(SlhDsaPrivateKey::CreateFromSeed(
                    test_private_key->GetPublicKey().GetParameters(), seed,
                    /*id_requirement=*/123, GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SlhDsaPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  RestrictedData restricted_private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(63), InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*parameters, restricted_private_key_bytes,
                               /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("SLH-DSA private key length must be "
                         "64, 96, or 128 bytes.")));
}

TEST_P(SlhDsaPrivateKeyTest,
       CreateFromParametersWithMismatchedIdRequirementFails) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  if (test_private_key->GetParameters().HasIdRequirement()) {
    EXPECT_THAT(SlhDsaPrivateKey::Create(
                    test_private_key->GetPublicKey().GetParameters(),
                    test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
                    /*id_requirement=*/std::nullopt, GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(SlhDsaPrivateKey::Create(
                    test_private_key->GetPublicKey().GetParameters(),
                    test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
                    /*id_requirement=*/123, GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(SlhDsaPrivateKeyTest, CreateWithInvalidPublicKeyAndPrivateKeyLengthFails) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, subtle::Random::GetRandomBytes(32),
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData restricted_private_key_bytes(63);
  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*public_key, restricted_private_key_bytes,
                               GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("SLH-DSA private key length must be "
                         "64, 96, or 128 bytes.")));
}

TEST(SlhDsaPrivateKeyTest, CreateWithMismatchedPairFails) {
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());

  std::string mismatched_private_key_bytes =
      std::string(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())
                      .GetSecret(InsecureSecretKeyAccess::Get()));
  mismatched_private_key_bytes[32] ^= 1;
  RestrictedData restricted_private_key_bytes = RestrictedData(
      mismatched_private_key_bytes, InsecureSecretKeyAccess::Get());

  // Creating the private key using the different private_key_bytes should fail.
  EXPECT_THAT(SlhDsaPrivateKey::Create(test_private_key->GetPublicKey(),
                                       restricted_private_key_bytes,
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid SLH-DSA key pair")));
}

TEST(SlhDsaPrivateKeyTest, CreateWithModifiedPrivateKeyFails) {
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());

  std::string private_key_bytes =
      std::string(test_private_key->GetPrivateKeyBytes(GetPartialKeyAccess())
                      .GetSecret(InsecureSecretKeyAccess::Get()));
  // Replace last 16 bytes of the private key bytes with random bytes.
  private_key_bytes.replace(/*seed_size=*/48, /*pk_root_size=*/16,
                            subtle::Random::GetRandomBytes(16));
  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(SlhDsaPrivateKey::Create(test_private_key->GetPublicKey(),
                                       restricted_private_key_bytes,
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid SLH-DSA key pair")));
}

TEST_P(SlhDsaPrivateKeyTest, KeyEquals) {
  const internal::SignatureTestVector& test_vector = GetParam();
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      test_vector.signature_private_key.get());

  SlhDsaPrivateKey copy = *test_private_key;

  EXPECT_TRUE(*test_private_key == copy);
  EXPECT_TRUE(copy == *test_private_key);
  EXPECT_FALSE(*test_private_key != copy);
  EXPECT_FALSE(copy != *test_private_key);
}

TEST(SlhDsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  const auto* key1 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());
  const auto* key2 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kNoPrefix)
          .signature_private_key.get());

  EXPECT_TRUE(*key1 != *key2);
  EXPECT_TRUE(*key2 != *key1);
  EXPECT_FALSE(*key1 == *key2);
  EXPECT_FALSE(*key2 == *key1);
}

TEST(SlhDsaPrivateKeyTest, Clone) {
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = test_private_key->Clone();

  EXPECT_THAT(*cloned_key, Eq(*test_private_key));
}

TEST(SlhDsaPrivateKeyTest, CopyConstructor) {
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());

  SlhDsaPrivateKey copy(*test_private_key);

  EXPECT_THAT(copy, Eq(*test_private_key));
}

TEST(SlhDsaPrivateKeyTest, CopyAssignment) {
  const auto* key1 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());
  const auto* key2 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kShake,
          SlhDsaParameters::SignatureType::kFastSigning,
          SlhDsaParameters::Variant::kNoPrefix)
          .signature_private_key.get());

  SlhDsaPrivateKey copy = *key2;
  copy = *key1;

  EXPECT_THAT(copy, Eq(*key1));
}

TEST(SlhDsaPrivateKeyTest, MoveConstructor) {
  const auto* test_private_key = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());

  SlhDsaPrivateKey key = *test_private_key;
  SlhDsaPrivateKey expected = key;
  SlhDsaPrivateKey moved(std::move(key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(SlhDsaPrivateKeyTest, MoveAssignment) {
  const auto* key1 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kSha2,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kTink)
          .signature_private_key.get());
  const auto* key2 = static_cast<const SlhDsaPrivateKey*>(
      internal::GetSlhDsaTestVector(
          SlhDsaParameters::HashType::kShake,
          SlhDsaParameters::SignatureType::kFastSigning,
          SlhDsaParameters::Variant::kNoPrefix)
          .signature_private_key.get());

  SlhDsaPrivateKey key = *key1;
  SlhDsaPrivateKey other_key = *key2;
  SlhDsaPrivateKey expected = key;
  other_key = std::move(key);

  EXPECT_THAT(other_key, Eq(expected));
}
#endif  // TINK_USE_ONLY_FIPS

}  // namespace
}  // namespace tink
}  // namespace crypto
