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

#include "tink/aead/internal/chacha20_poly1305_key_creator.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/aead/chacha20_poly1305_key.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/testing/aead_test_vector.h"
#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

struct TestCase {
  std::string name;
  const AeadTestVector& test_vector;
};

using ChaCha20Poly1305KeyCreatorParameterizedTest = TestWithParam<TestCase>;

TEST_P(ChaCha20Poly1305KeyCreatorParameterizedTest, CreateKeyWorks) {
  const auto* expected_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetParam().test_vector.aead_key.get());
  ASSERT_NE(expected_key, nullptr);

  absl::StatusOr<std::unique_ptr<Key>> key = CreateChaCha20Poly1305Key(
      expected_key->GetParameters(), expected_key->GetIdRequirement());
  ASSERT_THAT(key, IsOk());

  const auto* chacha20_poly1305_key =
      dynamic_cast<const ChaCha20Poly1305Key*>(key->get());
  ASSERT_NE(chacha20_poly1305_key, nullptr);
  EXPECT_THAT(chacha20_poly1305_key->GetIdRequirement(),
              Eq(expected_key->GetIdRequirement()));
  EXPECT_THAT(chacha20_poly1305_key->GetParameters(),
              Eq(expected_key->GetParameters()));
  EXPECT_THAT(chacha20_poly1305_key->GetOutputPrefix(),
              Eq(expected_key->GetOutputPrefix()));
}

TEST_P(ChaCha20Poly1305KeyCreatorParameterizedTest,
       CreateKeyTwiceYieldsDifferentKeys) {
  const auto* expected_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetParam().test_vector.aead_key.get());
  ASSERT_NE(expected_key, nullptr);

  absl::StatusOr<std::unique_ptr<Key>> key1 = CreateChaCha20Poly1305Key(
      expected_key->GetParameters(), expected_key->GetIdRequirement());
  ASSERT_THAT(key1, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key2 = CreateChaCha20Poly1305Key(
      expected_key->GetParameters(), expected_key->GetIdRequirement());
  ASSERT_THAT(key2, IsOk());

  EXPECT_NE(**key1, **key2);
}

TEST_P(ChaCha20Poly1305KeyCreatorParameterizedTest,
       CreateKeyWithKeyGenConfigurationWorks) {
  const auto* expected_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetParam().test_vector.aead_key.get());
  ASSERT_NE(expected_key, nullptr);
  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddKeyCreator<ChaCha20Poly1305Parameters>(
          CreateChaCha20Poly1305Key, key_creator_config),
      IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key = KeyGenConfigurationImpl::CreateKey(
      expected_key->GetParameters(), expected_key->GetIdRequirement(),
      key_creator_config);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetParameters(), Eq(expected_key->GetParameters()));
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(expected_key->GetIdRequirement()));
}

INSTANTIATE_TEST_SUITE_P(
    ChaCha20Poly1305KeyCreatorParameterizedTests,
    ChaCha20Poly1305KeyCreatorParameterizedTest,
    ValuesIn<TestCase>({
        {/*name=*/"ChaCha20Poly1305Tink",
         /*test_vector=*/GetChaCha20Poly1305TestVector(
             ChaCha20Poly1305Parameters::Variant::kTink)},
        {/*name=*/"ChaCha20Poly1305Crunchy",
         /*test_vector=*/GetChaCha20Poly1305TestVector(
             ChaCha20Poly1305Parameters::Variant::kCrunchy)},
        {/*name=*/"ChaCha20Poly1305NoPrefix",
         /*test_vector=*/GetChaCha20Poly1305TestVector(
             ChaCha20Poly1305Parameters::Variant::kNoPrefix)},
    }),
    [](const TestParamInfo<TestCase>& info) { return info.param.name; });

TEST(ChaCha20Poly1305KeyCreatorTest, CreateKeyTinkWithoutIdRequirementFails) {
  const auto* tink_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetChaCha20Poly1305TestVector(ChaCha20Poly1305Parameters::Variant::kTink)
          .aead_key.get());
  ASSERT_NE(tink_key, nullptr);
  EXPECT_THAT(CreateChaCha20Poly1305Key(tink_key->GetParameters(),
                                        /*id_requirement=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyCreatorTest,
     CreateKeyCrunchyWithoutIdRequirementFails) {
  const auto* crunchy_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetChaCha20Poly1305TestVector(
          ChaCha20Poly1305Parameters::Variant::kCrunchy)
          .aead_key.get());
  ASSERT_NE(crunchy_key, nullptr);
  EXPECT_THAT(CreateChaCha20Poly1305Key(crunchy_key->GetParameters(),
                                        /*id_requirement=*/std::nullopt),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ChaCha20Poly1305KeyCreatorTest, CreateKeyNoPrefixWithIdRequirementFails) {
  const auto* no_prefix_key = dynamic_cast<const ChaCha20Poly1305Key*>(
      GetChaCha20Poly1305TestVector(
          ChaCha20Poly1305Parameters::Variant::kNoPrefix)
          .aead_key.get());
  ASSERT_NE(no_prefix_key, nullptr);
  EXPECT_THAT(CreateChaCha20Poly1305Key(no_prefix_key->GetParameters(), 123),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
