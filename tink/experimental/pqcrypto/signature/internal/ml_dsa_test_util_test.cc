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

#include "tink/experimental/pqcrypto/signature/internal/ml_dsa_test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;

TEST(MlDsaTestUtilTest, GenerateMlDsaPrivateKeyWorks) {
  util::StatusOr<MlDsaParameters> key_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key =
      GenerateMlDsaPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
