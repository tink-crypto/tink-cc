// Copyright 2022 Google LLC
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

#include "tink/internal/legacy_proto_key.h"

#include <memory>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/rtti.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::KeyMaterialTypeTP;
using ::crypto::tink::internal::OutputPrefixTypeTP;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

class LegacyProtoKeyTest : public ::testing::Test {
 protected:
  // Although this is a friend class, this utility function is necessary to
  // access `ProtoKeySerialization::EqualsWithPotentialFalseNegatives()`
  // since the test fixtures are subclasses that would not have direct access.
  bool Equals(ProtoKeySerialization serialization,
              ProtoKeySerialization other) {
    return serialization.EqualsWithPotentialFalseNegatives(other);
  }
};

TEST_F(LegacyProtoKeyTest, CreateAndSerialization) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetIdRequirement(), Eq(12345));
  EXPECT_THAT(key->GetParameters().HasIdRequirement(), IsTrue());
  EXPECT_THAT(key->Serialization(InsecureSecretKeyAccess::Get()), IsOk());

  absl::StatusOr<const ProtoKeySerialization&> key_serialization =
      key->Serialization(InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization.status(), IsOk());
  EXPECT_THAT(Equals(*key_serialization, *serialization), IsTrue());
}

TEST_F(LegacyProtoKeyTest, Equals) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key == *other_key);
  EXPECT_TRUE(*other_key == *key);
  EXPECT_FALSE(*key != *other_key);
  EXPECT_FALSE(*other_key != *key);
}

TEST_F(LegacyProtoKeyTest, TypeUrlNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("other_type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, SerializedKeyNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  RestrictedData other_serialized_key =
      RestrictedData("other_serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", other_serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, KeyMaterialTypeNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kRemote,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, OutputPrefixTypeNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kCrunchy,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, IdRequirementNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/6789);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(*key != *other_key);
  EXPECT_TRUE(*other_key != *key);
  EXPECT_FALSE(*key == *other_key);
  EXPECT_FALSE(*other_key == *key);
}

TEST_F(LegacyProtoKeyTest, Clone) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*key));
}

TEST_F(LegacyProtoKeyTest, ParametersEquals) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(key->GetParameters() == other_key->GetParameters());
  EXPECT_TRUE(other_key->GetParameters() == key->GetParameters());
  EXPECT_FALSE(key->GetParameters() != other_key->GetParameters());
  EXPECT_FALSE(other_key->GetParameters() != key->GetParameters());
}

TEST_F(LegacyProtoKeyTest, ParametersEqualsIgnoresKeySpecificFields) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  RestrictedData other_serialized_key =
      RestrictedData("other_serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", other_serialized_key,
                                    KeyMaterialTypeTP::kRemote,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/6789);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(key->GetParameters() == other_key->GetParameters());
  EXPECT_TRUE(other_key->GetParameters() == key->GetParameters());
  EXPECT_FALSE(key->GetParameters() != other_key->GetParameters());
  EXPECT_FALSE(other_key->GetParameters() != key->GetParameters());
}

TEST_F(LegacyProtoKeyTest, ParametersTypeUrlNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("other_type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(key->GetParameters() != other_key->GetParameters());
  EXPECT_TRUE(other_key->GetParameters() != key->GetParameters());
  EXPECT_FALSE(key->GetParameters() == other_key->GetParameters());
  EXPECT_FALSE(other_key->GetParameters() == key->GetParameters());
}

TEST_F(LegacyProtoKeyTest, ParametersOutputPrefixTypeNotEqual) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<ProtoKeySerialization> other_serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kCrunchy,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(other_serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> other_key = LegacyProtoKey::Create(
      *other_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(other_key.status(), IsOk());

  EXPECT_TRUE(key->GetParameters() != other_key->GetParameters());
  EXPECT_TRUE(other_key->GetParameters() != key->GetParameters());
  EXPECT_FALSE(key->GetParameters() == other_key->GetParameters());
  EXPECT_FALSE(other_key->GetParameters() == key->GetParameters());
}

TEST_F(LegacyProtoKeyTest, ParametersDifferentTypeNotEqual) {
  class OtherParameters : public Parameters {
   public:
    bool HasIdRequirement() const override { return true; }
    bool operator==(const Parameters&) const override {
      ADD_FAILURE() << "Do not call";
      return false;
    }
    std::unique_ptr<Parameters> Clone() const override { return nullptr; }
  };

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  OtherParameters other_parameters;
  EXPECT_TRUE(key->GetParameters() != other_parameters);
  EXPECT_FALSE(key->GetParameters() == other_parameters);
}

TEST_F(LegacyProtoKeyTest, ParametersClone) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  std::unique_ptr<Parameters> cloned_parameters = key->GetParameters().Clone();
  ASSERT_THAT(cloned_parameters, NotNull());
  EXPECT_TRUE(*cloned_parameters == key->GetParameters());
  EXPECT_TRUE(key->GetParameters() == *cloned_parameters);
}

using AllOutputPrefixTypesTest =
    TestWithParam<std::tuple<OutputPrefixTypeTP, absl::optional<int>>>;

INSTANTIATE_TEST_SUITE_P(
    AllOutputPrefixTypesTestSuite, AllOutputPrefixTypesTest,
    Values(std::make_tuple(OutputPrefixTypeTP::kRaw, std::nullopt),
           std::make_tuple(OutputPrefixTypeTP::kTink, 123),
           std::make_tuple(OutputPrefixTypeTP::kCrunchy, 456),
           std::make_tuple(OutputPrefixTypeTP::kLegacy, 789)));

TEST_P(AllOutputPrefixTypesTest, GetIdRequirement) {
  OutputPrefixTypeTP output_prefix_type;
  absl::optional<int> id_requirement;
  std::tie(output_prefix_type, id_requirement) = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    output_prefix_type, id_requirement);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  EXPECT_THAT(key->GetIdRequirement(), Eq(id_requirement));
}

using AllKeyMaterialTypesTest = TestWithParam<KeyMaterialTypeTP>;

INSTANTIATE_TEST_SUITE_P(AllKeyMaterialTypesTestSuite, AllKeyMaterialTypesTest,
                         Values(KeyMaterialTypeTP::kSymmetric,
                                KeyMaterialTypeTP::kAsymmetricPrivate,
                                KeyMaterialTypeTP::kAsymmetricPublic,
                                KeyMaterialTypeTP::kRemote));

TEST_P(AllKeyMaterialTypesTest, CreateAndSerializationWithSecretAccessToken) {
  KeyMaterialTypeTP key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<const ProtoKeySerialization&> key_serialization =
      key->Serialization(InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization.status(), IsOk());
}

using SecretKeyMaterialTypesTest = TestWithParam<KeyMaterialTypeTP>;

INSTANTIATE_TEST_SUITE_P(SecretKeyMaterialTypesTestSuite,
                         SecretKeyMaterialTypesTest,
                         Values(KeyMaterialTypeTP::kSymmetric,
                                KeyMaterialTypeTP::kAsymmetricPrivate));

TEST_P(SecretKeyMaterialTypesTest, CreateWithoutSecretAccessToken) {
  KeyMaterialTypeTP key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(SecretKeyMaterialTypesTest, SerializationWithoutSecretAccessToken) {
  KeyMaterialTypeTP key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  // Must use token for key creation.
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<const ProtoKeySerialization&> key_serialization =
      key->Serialization(/*token=*/std::nullopt);
  ASSERT_THAT(key_serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

using NonSecretKeyMaterialTypesTest = TestWithParam<KeyMaterialTypeTP>;

INSTANTIATE_TEST_SUITE_P(NonSecretKeyMaterialTypesTestSuite,
                         NonSecretKeyMaterialTypesTest,
                         Values(KeyMaterialTypeTP::kAsymmetricPublic,
                                KeyMaterialTypeTP::kRemote));

TEST_P(NonSecretKeyMaterialTypesTest, CreateWithoutSecretAccessToken) {
  KeyMaterialTypeTP key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key.status(), IsOk());
}

TEST_P(NonSecretKeyMaterialTypesTest, SerializationWithoutSecretAccessToken) {
  KeyMaterialTypeTP key_material_type = GetParam();

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    key_material_type,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());

  // Must use token for key creation.
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<const ProtoKeySerialization&> key_serialization =
      key->Serialization(/*token=*/std::nullopt);
  ASSERT_THAT(key_serialization.status(), IsOk());
}

TEST_F(LegacyProtoKeyTest, DynamicCastAndTypeIndex) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/12345);
  ASSERT_THAT(serialization.status(), IsOk());
  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  const Key* base_key = &*key;
  EXPECT_THAT(GetTypeIndex(*base_key),
              Eq(GetStaticTypeIndex<LegacyProtoKey>()));
  EXPECT_THAT(DynamicCast<const Key*>(base_key), Eq(&*key));
  EXPECT_THAT(DynamicCast<const LegacyProtoKey*>(base_key), Eq(&*key));
  EXPECT_THAT(DynamicCast<const NoIdKey*>(base_key), IsNull());
  EXPECT_FALSE(*key == NoIdKey());

  const Parameters* base_params = &key->GetParameters();
  EXPECT_THAT(GetTypeIndex(*base_params),
              Eq(GetStaticTypeIndex<UnusableLegacyProtoParameters>()));
  EXPECT_THAT(DynamicCast<const Parameters*>(base_params), Eq(base_params));
  EXPECT_THAT(DynamicCast<const UnusableLegacyProtoParameters*>(base_params),
              Eq(base_params));
  EXPECT_THAT(DynamicCast<const NoIdParams*>(base_params), IsNull());
  EXPECT_FALSE(*base_params == NoIdParams());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
