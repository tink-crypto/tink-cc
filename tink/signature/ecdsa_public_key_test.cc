// Copyright 2024 Google LLC
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

#include "tink/signature/ecdsa_public_key.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

// Returns static EC public key from GetEcdsaTestVector() for the given curve.
const EcdsaPublicKey& GetTestPublicKey(EcdsaParameters::CurveType curve_type) {
  if (curve_type == EcdsaParameters::CurveType::kNistP256) {
    const EcdsaPublicKey* key = dynamic_cast<const EcdsaPublicKey*>(
        &internal::GetEcdsaTestVector(
             EcdsaParameters::CurveType::kNistP256,
             EcdsaParameters::HashType::kSha256,
             EcdsaParameters::SignatureEncoding::kIeeeP1363,
             EcdsaParameters::Variant::kNoPrefix)
             .signature_private_key->GetPublicKey());
    ABSL_CHECK_NE(key, nullptr);
    return *key;
  }
  if (curve_type == EcdsaParameters::CurveType::kNistP384) {
    const EcdsaPublicKey* key = dynamic_cast<const EcdsaPublicKey*>(
        &internal::GetEcdsaTestVector(
             EcdsaParameters::CurveType::kNistP384,
             EcdsaParameters::HashType::kSha384,
             EcdsaParameters::SignatureEncoding::kIeeeP1363,
             EcdsaParameters::Variant::kNoPrefix)
             .signature_private_key->GetPublicKey());
    ABSL_CHECK_NE(key, nullptr);
    return *key;
  }
  if (curve_type == EcdsaParameters::CurveType::kNistP521) {
    const EcdsaPublicKey* key = dynamic_cast<const EcdsaPublicKey*>(
        &internal::GetEcdsaTestVector(
             EcdsaParameters::CurveType::kNistP521,
             EcdsaParameters::HashType::kSha512,
             EcdsaParameters::SignatureEncoding::kIeeeP1363,
             EcdsaParameters::Variant::kNoPrefix)
             .signature_private_key->GetPublicKey());
    ABSL_CHECK_NE(key, nullptr);
    return *key;
  }
  ABSL_LOG(FATAL) << "Unsupported curve type";
}

// Test case for P-256 downloaded from NIST CAVP.
const EcPoint& GetP256EcPoint() {
  static const absl::NoDestructor<EcPoint> point(
      BigInteger(test::HexDecodeOrDie(
          "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287")),
      BigInteger(test::HexDecodeOrDie(
          "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac")));
  return *point;
}

struct TestCase {
  EcdsaParameters::CurveType curve_type;
  EcdsaParameters::HashType hash_type;
  EcdsaParameters::SignatureEncoding signature_encoding;
  EcdsaParameters::Variant variant;
  std::optional<int> id_requirement;
  std::string output_prefix;
};

using EcdsaPublicKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    EcdsaPublicKeyTestSuite, EcdsaPublicKeyTest,
    Values(TestCase{EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{EcdsaParameters::CurveType::kNistP384,
                    EcdsaParameters::HashType::kSha384,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{EcdsaParameters::CurveType::kNistP521,
                    EcdsaParameters::HashType::kSha512,
                    EcdsaParameters::SignatureEncoding::kIeeeP1363,
                    EcdsaParameters::Variant::kNoPrefix,
                    /*id_requirement=*/std::nullopt,
                    /*output_prefix=*/""},
           TestCase{EcdsaParameters::CurveType::kNistP256,
                    EcdsaParameters::HashType::kSha256,
                    EcdsaParameters::SignatureEncoding::kDer,
                    EcdsaParameters::Variant::kNoPrefixWithPrehashId,
                    /*id_requirement=*/0x123,
                    /*output_prefix=*/""}));

TEST_P(EcdsaPublicKeyTest, CreatePublicKeyWorks) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  const EcdsaPublicKey& test_key = GetTestPublicKey(test_case.curve_type);

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, test_key.GetPublicPoint(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EXPECT_THAT(public_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(public_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(public_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(public_key->GetPublicPoint(GetPartialKeyAccess()),
              Eq(test_key.GetPublicPoint(GetPartialKeyAccess())));
}

TEST(EcdsaPublicKeyTest, CreatePublicKeyWithInvalidIdRequirementFails) {
  absl::StatusOr<EcdsaParameters> no_prefix_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(no_prefix_params, IsOk());

  absl::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  EXPECT_THAT(
      EcdsaPublicKey::Create(*no_prefix_params, GetP256EcPoint(),
                             /*id_requirement=*/123, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key with ID requirement with parameters without ID "
                         "requirement")));

  EXPECT_THAT(EcdsaPublicKey::Create(*tink_params, GetP256EcPoint(),
                                     /*id_requirement=*/std::nullopt,
                                     GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key without ID requirement with parameters "
                                 "with ID requirement")));
}

TEST(EcdsaPublicKeyTest, CreatePublicKeyWithInvalidPointFails) {
  // Creates an invalid EC point, by modifying the Y coordinate of
  // GetP256EcPoint().
  EcPoint invalid_point(
      BigInteger(test::HexDecodeOrDie(
          "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287")),
      BigInteger(test::HexDecodeOrDie(
          "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ad")));

  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, invalid_point,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  EXPECT_THAT(public_key.status(), StatusIs(absl::StatusCode::kInternal));
}

TEST_P(EcdsaPublicKeyTest, PublicKeyEquals) {
  TestCase test_case = GetParam();

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetSignatureEncoding(test_case.signature_encoding)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  const EcdsaPublicKey& test_key = GetTestPublicKey(test_case.curve_type);

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *parameters, test_key.GetPublicPoint(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaPublicKey> other_public_key = EcdsaPublicKey::Create(
      *parameters, test_key.GetPublicPoint(GetPartialKeyAccess()),
      test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key == *other_public_key);
  EXPECT_TRUE(*other_public_key == *public_key);
  EXPECT_FALSE(*public_key != *other_public_key);
  EXPECT_FALSE(*other_public_key != *public_key);
}

TEST(EcdsaPublicKeyTest, DifferentParametersNotEqual) {
  absl::StatusOr<EcdsaParameters> crunchy_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kCrunchy)
          .Build();
  ASSERT_THAT(crunchy_params, IsOk());

  absl::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  absl::StatusOr<EcdsaPublicKey> crunchy_public_key = EcdsaPublicKey::Create(
      *crunchy_params, GetP256EcPoint(),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(crunchy_public_key, IsOk());

  absl::StatusOr<EcdsaPublicKey> tink_public_key = EcdsaPublicKey::Create(
      *tink_params, GetP256EcPoint(),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(tink_public_key, IsOk());

  EXPECT_TRUE(*tink_public_key != *crunchy_public_key);
  EXPECT_TRUE(*crunchy_public_key != *tink_public_key);
  EXPECT_FALSE(*tink_public_key == *crunchy_public_key);
  EXPECT_FALSE(*crunchy_public_key == *tink_public_key);
}

TEST(EcdsaPublicKeyTest, DifferentPublicPointsNotEqual) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());

  const EcdsaPublicKey& test_key =
      GetTestPublicKey(EcdsaParameters::CurveType::kNistP256);

  EcPoint public_point1 = test_key.GetPublicPoint(GetPartialKeyAccess());
  EcPoint public_point2 = GetP256EcPoint();

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, public_point1,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaPublicKey> other_public_key = EcdsaPublicKey::Create(
      *params, public_point2,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EcdsaPublicKeyTest, DifferentIdRequirementsNotEqual) {
  absl::StatusOr<EcdsaParameters> tink_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *tink_params, GetP256EcPoint(),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaPublicKey> other_public_key = EcdsaPublicKey::Create(
      *tink_params, GetP256EcPoint(),
      /*id_requirement=*/0x02030405, GetPartialKeyAccess());
  ASSERT_THAT(other_public_key, IsOk());

  EXPECT_TRUE(*public_key != *other_public_key);
  EXPECT_TRUE(*other_public_key != *public_key);
  EXPECT_FALSE(*public_key == *other_public_key);
  EXPECT_FALSE(*other_public_key == *public_key);
}

TEST(EcdsaPublicKeyTest, Clone) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, GetP256EcPoint(),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = public_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*public_key));
}

TEST(EcdsaPublicKeyTest, CopyConstructor) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, GetP256EcPoint(), /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EcdsaPublicKey copy(*public_key);

  EXPECT_THAT(copy, Eq(*public_key));
}

TEST(EcdsaPublicKeyTest, CopyAssignment) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, GetP256EcPoint(), /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaParameters> other_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kLegacy)
          .Build();
  ASSERT_THAT(other_params, IsOk());

  const EcdsaPublicKey& other_test_key =
      GetTestPublicKey(EcdsaParameters::CurveType::kNistP384);

  absl::StatusOr<EcdsaPublicKey> copy = EcdsaPublicKey::Create(
      *other_params, other_test_key.GetPublicPoint(GetPartialKeyAccess()),
      /*id_requirement=*/0x05060708, GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *public_key;

  EXPECT_THAT(*copy, Eq(*public_key));
}

TEST(EcdsaPublicKeyTest, MoveConstructor) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, GetP256EcPoint(), /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  EcdsaPublicKey expected = *public_key;
  EcdsaPublicKey moved(std::move(*public_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(EcdsaPublicKeyTest, MoveAssignment) {
  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      *params, GetP256EcPoint(), /*id_requirement=*/0x01020304,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaParameters> other_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kLegacy)
          .Build();
  ASSERT_THAT(other_params, IsOk());

  const EcdsaPublicKey& other_test_key =
      GetTestPublicKey(EcdsaParameters::CurveType::kNistP384);

  absl::StatusOr<EcdsaPublicKey> moved = EcdsaPublicKey::Create(
      *other_params, other_test_key.GetPublicPoint(GetPartialKeyAccess()),
      /*id_requirement=*/0x05060708, GetPartialKeyAccess());
  ASSERT_THAT(moved, IsOk());

  EcdsaPublicKey expected(*public_key);
  *moved = std::move(*public_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
