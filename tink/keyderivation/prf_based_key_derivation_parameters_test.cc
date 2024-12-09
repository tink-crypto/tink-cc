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

#include "tink/keyderivation/prf_based_key_derivation_parameters.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/parameters.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;

TEST(PrfBasedKeyDerivationParametersTest, Build) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(parameters->GetPrfParameters(), Eq(*prf_parameters));
  EXPECT_THAT(parameters->GetDerivedKeyParameters(),
              Eq(*derived_key_parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, BuildWithoutPrfParametersFails) {
  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  EXPECT_THAT(PrfBasedKeyDerivationParameters::Builder()
                  .SetDerivedKeyParameters(*derived_key_parameters)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("PRF parameters must be set")));
}

TEST(PrfBasedKeyDerivationParametersTest,
     BuildWithoutDerivedKeyParametersFails) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  EXPECT_THAT(PrfBasedKeyDerivationParameters::Builder()
                  .SetPrfParameters(*prf_parameters)
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Derived key parameters must be set")));
}

TEST(PrfBasedKeyDerivationParametersTest, CopyConstructor) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  PrfBasedKeyDerivationParameters copy(*parameters);

  EXPECT_THAT(copy.GetPrfParameters(), Eq(*prf_parameters));
  EXPECT_THAT(copy.GetDerivedKeyParameters(), Eq(*derived_key_parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, CopyAssignment) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacPrfParameters> prf_parameters2 = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha224);
  ASSERT_THAT(prf_parameters2, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> derived_key_parameters2 =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> copy =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters2)
          .SetDerivedKeyParameters(*derived_key_parameters2)
          .Build();
  ASSERT_THAT(copy, IsOk());

  copy = parameters;

  EXPECT_THAT(copy->GetPrfParameters(), Eq(*prf_parameters));
  EXPECT_THAT(copy->GetDerivedKeyParameters(), Eq(*derived_key_parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, MoveConstructor) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  PrfBasedKeyDerivationParameters move(std::move(*parameters));

  EXPECT_THAT(move.GetPrfParameters(), Eq(*prf_parameters));
  EXPECT_THAT(move.GetDerivedKeyParameters(), Eq(*derived_key_parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, MoveAssignment) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<HmacPrfParameters> prf_parameters2 = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha224);
  ASSERT_THAT(prf_parameters2, IsOk());

  util::StatusOr<ChaCha20Poly1305Parameters> derived_key_parameters2 =
      ChaCha20Poly1305Parameters::Create(
          ChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters2, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> move =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters2)
          .SetDerivedKeyParameters(*derived_key_parameters2)
          .Build();
  ASSERT_THAT(move, IsOk());

  move = std::move(parameters);

  EXPECT_THAT(move->GetPrfParameters(), Eq(*prf_parameters));
  EXPECT_THAT(move->GetDerivedKeyParameters(), Eq(*derived_key_parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, Clone) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::unique_ptr<Parameters> clone = parameters->Clone();

  EXPECT_THAT(*clone, Eq(*parameters));
}

TEST(PrfBasedKeyDerivationParametersTest, ParametersEquals) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> other_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters == *other_parameters);
  EXPECT_TRUE(*other_parameters == *parameters);
  EXPECT_FALSE(*parameters != *other_parameters);
  EXPECT_FALSE(*other_parameters != *parameters);
}

TEST(PrfBasedKeyDerivationParametersTest, DifferentPrfParametersNotEqual) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

  util::StatusOr<AesCmacPrfParameters> other_prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/16);
  ASSERT_THAT(other_prf_parameters, IsOk());

  util::StatusOr<XChaCha20Poly1305Parameters> derived_key_parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ASSERT_THAT(derived_key_parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> other_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*other_prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

TEST(PrfBasedKeyDerivationParametersTest,
     DifferentDerivedKeyParametersNotEqual) {
  util::StatusOr<AesCmacPrfParameters> prf_parameters =
      AesCmacPrfParameters::Create(/*key_size_in_bytes=*/32);
  ASSERT_THAT(prf_parameters, IsOk());

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
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> other_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(*prf_parameters)
          .SetDerivedKeyParameters(*other_derived_key_parameters)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  EXPECT_TRUE(*parameters != *other_parameters);
  EXPECT_FALSE(*parameters == *other_parameters);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
