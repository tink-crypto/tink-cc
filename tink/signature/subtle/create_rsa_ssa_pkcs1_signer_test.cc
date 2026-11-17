// Copyright 2026 Google LLC
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

#include "tink/signature/subtle/create_rsa_ssa_pkcs1_signer.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;

using CreateRsaSsaPkcs1PublicKeySignTestVectorTest =
    testing::TestWithParam<internal::SignatureTestVector>;

TEST_P(CreateRsaSsaPkcs1PublicKeySignTestVectorTest,
       ComputeSignatureInTestVector) {
  const internal::SignatureTestVector& param = GetParam();
  const RsaSsaPkcs1PrivateKey* typed_key =
      dynamic_cast<const RsaSsaPkcs1PrivateKey*>(
          param.signature_private_key.get());
  ASSERT_THAT(typed_key, NotNull());
  if (internal::IsFipsModeEnabled() &&
      typed_key->GetParameters().GetModulusSizeInBits() != 2048 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 3072 &&
      typed_key->GetParameters().GetModulusSizeInBits() != 4096) {
    ASSERT_THAT(CreateRsaSsaPkcs1PublicKeySign(*typed_key), Not(IsOk()));
    return;
  }
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    ASSERT_THAT(CreateRsaSsaPkcs1PublicKeySign(*typed_key), Not(IsOk()));
    return;
  }
  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      CreateRsaSsaPkcs1PublicKeySign(*typed_key);
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(param.message);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(*signature, Eq(param.signature));
}

INSTANTIATE_TEST_SUITE_P(
    CreateRsaSsaPkcs1PublicKeySignTestVectorTest,
    CreateRsaSsaPkcs1PublicKeySignTestVectorTest,
    testing::ValuesIn(internal::CreateRsaSsaPkcs1TestVectors()));

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
