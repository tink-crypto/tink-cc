// Copyright 2026 Google LLC
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

#include "tink/signature/internal/composite_ml_dsa_util_boringssl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::testing::Eq;

TEST(CompositeMlDsaUtilBoringSslTest, GetCompositeMlDsaLabelWorks) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::string> label = GetCompositeMlDsaLabel(*parameters);
  ASSERT_THAT(label, IsOk());

  EXPECT_THAT(*label, Eq("COMPSIG-MLDSA65-Ed25519-SHA512"));
}

TEST(CompositeMlDsaUtilBoringSslTest, ComputeCompositeMlDsaMessagePrimeWorks) {
  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::string> label = GetCompositeMlDsaLabel(*parameters);
  ASSERT_THAT(label, IsOk());

  // Test vector from
  // https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14#appendix-D
  std::string message = HexDecodeOrDie("00010203040506070809");
  std::string expected_message_prime = HexDecodeOrDie(
      "436f6d706f73697465416c676f726974686d5369676e61747572657332303235434f4d50"
      "5349472d4d4c44534136352d45434453412d503235362d534841353132000f89ee1fcb7b"
      "0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f9a3f202f56fadba4cd9e8d65"
      "4ab9f2e96dc5c795ea176fa20ede8d854c342f903533");

  std::string message_prime =
      ComputeCompositeMlDsaMessagePrime(*label, message);

  EXPECT_THAT(message_prime, Eq(expected_message_prime));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
