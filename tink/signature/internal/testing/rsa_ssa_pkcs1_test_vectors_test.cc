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

#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"

#include <cstddef>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/signature_private_key.h"
#include "tink/signature/signature_public_key.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::NotNull;

TEST(RsaSsaPkcs1TestVectorsTest, VerifyOnlyVectorsMatchFullVectors) {
  std::vector<SignatureTestVector> full_vectors =
      CreateRsaSsaPkcs1TestVectors();
  std::vector<SignatureVerifyOnlyTestVector> verify_only_vectors =
      CreateRsaSsaPkcs1VerifyOnlyTestVectors();

  EXPECT_THAT(full_vectors, Not(IsEmpty()));
  ASSERT_THAT(verify_only_vectors.size(), Eq(full_vectors.size()));
  for (std::size_t i = 0; i < full_vectors.size(); ++i) {
    ASSERT_THAT(full_vectors[i].signature_private_key, NotNull())
        << "index " << i;
    ASSERT_THAT(verify_only_vectors[i].signature_public_key, NotNull())
        << "index " << i;
    EXPECT_EQ(*verify_only_vectors[i].signature_public_key,
              full_vectors[i].signature_private_key->GetPublicKey())
        << "index " << i;
    EXPECT_THAT(verify_only_vectors[i].signature, Eq(full_vectors[i].signature))
        << "index " << i;
    EXPECT_THAT(verify_only_vectors[i].message, Eq(full_vectors[i].message))
        << "index " << i;
    EXPECT_THAT(verify_only_vectors[i].prehash, Eq(full_vectors[i].prehash))
        << "index " << i;
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
