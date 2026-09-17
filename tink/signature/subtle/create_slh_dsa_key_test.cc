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

#include "tink/signature/subtle/create_slh_dsa_key.h"

#include <optional>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;

TEST(CreateSlhDsaKeyTest, CreateSlhDsaPrivateKeyWorks) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> private_key =
      CreateSlhDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(123));
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateSlhDsaKeyTest, CreateSlhDsaPrivateKeyWithoutIdRequirement) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> private_key =
      CreateSlhDsaPrivateKey(*parameters);
  ASSERT_THAT(private_key, IsOk());
  EXPECT_THAT(private_key->GetIdRequirement().has_value(), IsFalse());
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
}

TEST(CreateSlhDsaKeyTest,
     CreateSlhDsaPrivateKeyMissingIdRequirementForTinkFails) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateSlhDsaPrivateKey(*parameters),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateSlhDsaKeyTest,
     CreateSlhDsaPrivateKeyIdRequirementGivenForNoPrefixFails) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(CreateSlhDsaPrivateKey(*parameters, /*id_requirement=*/123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateSlhDsaKeyTest, CreateSlhDsaPrivateKeySuccessiveKeysAreDistinct) {
  absl::StatusOr<SlhDsaParameters> parameters =
      SlhDsaParameters::Create(SlhDsaParameters::HashType::kSha2,
                               /*private_key_size_in_bytes=*/64,
                               SlhDsaParameters::SignatureType::kSmallSignature,
                               SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> key1 =
      CreateSlhDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key1, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> key2 =
      CreateSlhDsaPrivateKey(*parameters, /*id_requirement=*/123);
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(*key1, *key2);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
