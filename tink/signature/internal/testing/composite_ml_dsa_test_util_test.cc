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

#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"

#include "gtest/gtest.h"
#include "absl/types/optional.h"
#include "tink/signature/composite_ml_dsa_parameters.h"

namespace {

TEST(CompositeMlDsaTestUtilTest, GenerateMlDsaPrivateKeyForTestRuns) {
  (void)crypto::tink::internal::GenerateMlDsaPrivateKeyForTestOrDie(
      crypto::tink::CompositeMlDsaParameters::MlDsaInstance::kMlDsa65);
}

TEST(CompositeMlDsaTestUtilTest, GenerateClassicalPrivateKeyForTestRuns) {
  (void)crypto::tink::internal::GenerateClassicalPrivateKeyForTestOrDie(
      crypto::tink::CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
      /*force_random=*/false);
}

TEST(CompositeMlDsaTestUtilTest, GenerateCompositeMlDsaPrivateKeyForTestRuns) {
  (void)crypto::tink::internal::GenerateCompositeMlDsaPrivateKeyForTestOrDie(
      crypto::tink::CompositeMlDsaParameters::Create(
          crypto::tink::CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          crypto::tink::CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          crypto::tink::CompositeMlDsaParameters::Variant::kNoPrefix)
          .value(),
      /*force_random=*/false, /*id_requirement=*/absl::nullopt);
}

}  // namespace
