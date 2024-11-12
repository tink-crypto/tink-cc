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
////////////////////////////////////////////////////////////////////////////////
#include "tink/signature/internal/key_creators.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/optional.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/signature/internal/ml_dsa_proto_serialization.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using KeyCreatorsTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    KeyCreatorsTestSuite, KeyCreatorsTest,
    Values(TestCase{0x02030400, std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{absl::nullopt, ""}));

TEST_P(KeyCreatorsTest, CreateMlDsaPrivateKeyWorks) {
  TestCase test_case = GetParam();

  MlDsaParameters::Variant variant = test_case.id_requirement.has_value()
                                         ? MlDsaParameters::Variant::kTink
                                         : MlDsaParameters::Variant::kNoPrefix;
  util::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      CreateMlDsaKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
}

TEST_P(KeyCreatorsTest, CreateKeysetHandleFromConfigWithMlDsaKeyWorks) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());
  TestCase test_case = GetParam();

  MlDsaParameters::Variant variant = test_case.id_requirement.has_value()
                                         ? MlDsaParameters::Variant::kTink
                                         : MlDsaParameters::Variant::kNoPrefix;
  util::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  ASSERT_THAT(parameters, IsOk());

  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<MlDsaParameters>(
                  CreateMlDsaKey, key_creator_config),
              IsOk());

  KeysetHandleBuilder::Entry entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
          /*id=*/123);
  util::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry))
                                            .Build(key_creator_config);
  ASSERT_THAT(handle.status(), IsOk());

  EXPECT_THAT(*handle, SizeIs(1));
  EXPECT_THAT((*handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*handle)[0].GetId(), Eq(123));
  EXPECT_THAT((*handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*handle)[0].GetKey()->GetParameters(), Eq(*parameters));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto