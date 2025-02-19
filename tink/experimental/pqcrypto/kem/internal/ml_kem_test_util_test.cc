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

#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;

TEST(MlKemTestUtilTest, GenerateMlKemPrivateKeyWorks) {
  absl::StatusOr<MlKemParameters> key_parameters =
      MlKemParameters::Create(768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(key_parameters, IsOk());

  absl::StatusOr<MlKemPrivateKey> private_key =
      GenerateMlKemPrivateKey(*key_parameters, 0x42434445);
  ASSERT_THAT(private_key, IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
