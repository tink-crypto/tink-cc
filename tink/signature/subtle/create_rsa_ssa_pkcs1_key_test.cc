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
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/subtle/create_rsa_ssa_pkcs1_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/partial_key_access.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::Ne;

TEST(CreateRsaSsaPkcs1KeyTest, CreateRsaSsaPkcs1PrivateKeyWorks) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateRsaSsaPkcs1PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateRsaSsaPkcs1KeyTest,
     CreateRsaSsaPkcs1PrivateKeyWithoutIdRequirement) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateRsaSsaPkcs1PrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateRsaSsaPkcs1KeyTest,
     CreateRsaSsaPkcs1PrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateRsaSsaPkcs1PrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateRsaSsaPkcs1KeyTest,
     CreateRsaSsaPkcs1PrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateRsaSsaPkcs1PrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateRsaSsaPkcs1KeyTest,
     CreateRsaSsaPkcs1PrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> key1 =
      CreateRsaSsaPkcs1PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> key2 =
      CreateRsaSsaPkcs1PrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_THAT(key1->GetPublicKey().GetModulus(GetPartialKeyAccess()),
              Ne(key2->GetPublicKey().GetModulus(GetPartialKeyAccess())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
