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

#include "tink/keyderivation/prf_based_key_derivation_key.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
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

TEST(PrfBasedKeyDerivationKeyTest, CreateWithIdRequirement) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(key->GetIdRequirement(), Eq(123));
}

TEST(PrfBasedKeyDerivationKeyTest, CreateWithoutIdRequirement) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/absl::nullopt,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(key->GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(key->GetIdRequirement(), Eq(absl::nullopt));
}

TEST(PrfBasedKeyDerivationKeyTest, CreateWithMismatchedPrfParametersFails) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<AesCmacPrfParameters> mismatched_prf_parameters =
      AesCmacPrfParameters::Create(16);
  ASSERT_THAT(mismatched_prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*mismatched_prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(
                   "PrfParameters for `parameters` and `prf_key` must match")));
}

TEST(PrfBasedKeyDerivationKeyTest, CreateWithMismatchedIdRequirementFails) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> no_prefix_derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(no_prefix_derived_key_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> tink_derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(tink_derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> no_prefix_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*no_prefix_derived_key_parameters)
          .Build();
  ASSERT_THAT(no_prefix_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> tink_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*tink_derived_key_parameters)
          .Build();
  ASSERT_THAT(tink_parameters, IsOk());

  EXPECT_THAT(PrfBasedKeyDerivationKey::Create(*no_prefix_parameters, *prf_key,
                                               /*id_requirement=*/123,
                                               GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key with ID requirement")));
  EXPECT_THAT(PrfBasedKeyDerivationKey::Create(*tink_parameters, *prf_key,
                                               /*id_requirement=*/absl::nullopt,
                                               GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement")));
}

TEST(PrfBasedKeyDerivationKeyTest, CopyConstructor) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  PrfBasedKeyDerivationKey copy(*key);

  EXPECT_THAT(copy.GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy.GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(copy.GetIdRequirement(), Eq(123));
}

TEST(PrfBasedKeyDerivationKeyTest, CopyAssignment) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCmacPrfKey> prf_key2 =
      AesCmacPrfKey::Create(RestrictedData(16), GetPartialKeyAccess());
  ASSERT_THAT(prf_key2, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> derived_key_parameters2 =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(derived_key_parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters2 =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key2->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters2)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> copy =
      PrfBasedKeyDerivationKey::Create(*parameters2, *prf_key2,
                                       /*id_requirement=*/absl::nullopt,
                                       GetPartialKeyAccess());
  ASSERT_THAT(copy, IsOk());

  *copy = *key;

  EXPECT_THAT(copy->GetParameters(), Eq(*parameters));
  EXPECT_THAT(copy->GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(copy->GetIdRequirement(), Eq(123));
}

TEST(PrfBasedKeyDerivationKeyTest, MoveConstructor) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  PrfBasedKeyDerivationKey move(std::move(*key));

  EXPECT_THAT(move.GetParameters(), Eq(*parameters));
  EXPECT_THAT(move.GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(move.GetIdRequirement(), Eq(123));
}

TEST(PrfBasedKeyDerivationKeyTest, MoveAssignment) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<AesCmacPrfKey> prf_key2 =
      AesCmacPrfKey::Create(RestrictedData(16), GetPartialKeyAccess());
  ASSERT_THAT(prf_key2, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> derived_key_parameters2 =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(derived_key_parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters2 =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key2->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters2)
          .Build();
  ASSERT_THAT(parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> move =
      PrfBasedKeyDerivationKey::Create(*parameters2, *prf_key2,
                                       /*id_requirement=*/absl::nullopt,
                                       GetPartialKeyAccess());
  ASSERT_THAT(move, IsOk());

  *move = std::move(*key);

  EXPECT_THAT(move->GetParameters(), Eq(*parameters));
  EXPECT_THAT(move->GetPrfKey(), Eq(*prf_key));
  EXPECT_THAT(move->GetIdRequirement(), Eq(123));
}

TEST(PrfBasedKeyDerivationKeyTest, Clone) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  std::unique_ptr<Key> clone = key->Clone();

  EXPECT_THAT(*clone, Eq(*key));
}

TEST(PrfBasedKeyDerivationKeyTest, KeyEquals) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> other_key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST(PrfBasedKeyDerivationKeyTest, DifferentParametersNotEqual) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> other_derived_key_parameters =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(other_derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> other_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*other_derived_key_parameters)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> other_key =
      PrfBasedKeyDerivationKey::Create(*other_parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(PrfBasedKeyDerivationKeyTest, DifferentPrfKeyNotEqual) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<AesCmacPrfKey> other_prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(other_prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> other_key =
      PrfBasedKeyDerivationKey::Create(*parameters, *other_prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST(PrfBasedKeyDerivationKeyTest, DifferentIdRequirementNotEqual) {
  util::StatusOr<AesCmacPrfKey> prf_key =
      AesCmacPrfKey::Create(RestrictedData(32), GetPartialKeyAccess());
  ASSERT_THAT(prf_key, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(prf_key->GetParameters())
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<PrfBasedKeyDerivationKey> other_key =
      PrfBasedKeyDerivationKey::Create(*parameters, *prf_key,
                                       /*id_requirement=*/456,
                                       GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
