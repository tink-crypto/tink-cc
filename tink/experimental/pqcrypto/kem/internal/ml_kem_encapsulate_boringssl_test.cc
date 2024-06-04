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
///////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_encapsulate_boringssl.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_KYBER
#include "openssl/experimental/kyber.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/kem/internal/raw_kem_encapsulate.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

TEST(MlKemEncapsulateBoringSslTest, EncapsulationLengthsAreCorrect) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<RawKemEncapsulate>> encapsulate =
      NewMlKemEncapsulateBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<RawKemEncapsulation> kem_encasulation =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(kem_encasulation, IsOk());

  EXPECT_EQ(kem_encasulation->ciphertext.size(),
            KYBER_CIPHERTEXT_BYTES + private_key->GetOutputPrefix().size());
  EXPECT_EQ(kem_encasulation->shared_secret.size(), KYBER_SHARED_SECRET_BYTES);
}

TEST(MlKemEncapsulateBoringSslTest, EncapsulationIsNonDeterministic) {
  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<RawKemEncapsulate>> encapsulate =
      NewMlKemEncapsulateBoringSsl(private_key->GetPublicKey());
  ASSERT_THAT(encapsulate, IsOk());

  util::StatusOr<RawKemEncapsulation> kem_encasulation1 =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(kem_encasulation1, IsOk());

  util::StatusOr<RawKemEncapsulation> kem_encasulation2 =
      (*encapsulate)->Encapsulate();
  ASSERT_THAT(kem_encasulation2, IsOk());

  EXPECT_NE(kem_encasulation1->ciphertext, kem_encasulation2->ciphertext);
  EXPECT_NE(kem_encasulation1->shared_secret, kem_encasulation2->shared_secret);
}

TEST(MlKemEncapsulateBoringSslTest, FipsMode) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test assumes kOnlyUseFips.";
  }

  util::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());

  // Create a new encapsulator.
  EXPECT_THAT(
      NewMlKemEncapsulateBoringSsl(private_key->GetPublicKey()).status(),
      StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
