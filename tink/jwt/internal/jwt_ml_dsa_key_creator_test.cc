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

#include "tink/jwt/internal/jwt_ml_dsa_key_creator.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/jwt/jwt_ml_dsa_private_key.h"
#include "tink/jwt/jwt_ml_dsa_proto_serialization.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtMlDsaParameters::KidStrategy kid_strategy;
  JwtMlDsaParameters::Algorithm algorithm;
  absl::optional<int> id_requirement;
  absl::optional<std::string> expected_kid;
};

using KeyCreatorsTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    KeyCreatorsTestSuite, KeyCreatorsTest,
    Values(TestCase{JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                    JwtMlDsaParameters::Algorithm::kMlDsa44,
                    /*id_requirement=*/123, /*expected_kid=*/"AAAAew"},
           TestCase{JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
                    JwtMlDsaParameters::Algorithm::kMlDsa65,
                    /*id_requirement=*/123, /*expected_kid=*/"AAAAew"},
           TestCase{JwtMlDsaParameters::KidStrategy::kIgnored,
                    JwtMlDsaParameters::Algorithm::kMlDsa87,
                    /*id_requirement=*/std::nullopt,
                    /*expected_kid=*/std::nullopt}));

TEST_P(KeyCreatorsTest, CreateJwtMlDsaPrivateKey) {
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<JwtMlDsaPrivateKey>> private_key =
      CreateJwtMlDsaKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetParameters(), Eq(*parameters));
  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*private_key)->GetKid(), Eq(test_case.expected_kid));
}

TEST_P(KeyCreatorsTest, CreateKeysetHandleFromConfigWithJwtMlDsaKeyWorks) {
  ASSERT_THAT(RegisterJwtMlDsaProtoSerialization(), IsOk());
  TestCase test_case = GetParam();

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(test_case.kid_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<JwtMlDsaParameters>(
          CreateJwtMlDsaKey, key_creator_config),
      IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);
  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry))
                                            .Build(key_creator_config);
  ASSERT_THAT(handle, IsOk());

  ASSERT_THAT(*handle, SizeIs(1));
  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters(), Eq(*parameters));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
