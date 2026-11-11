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

#include "tink/internal/keyset_handle_builder_entry.h"

#include <sys/stat.h>

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_key_managers.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_proto.h"
#include "tink/util/test_matchers.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::KeyMaterialTypeTP;
using ::crypto::tink::internal::OutputPrefixTypeTP;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestOnlyKeyFormat;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Test;

absl::StatusOr<LegacyProtoParameters> CreateLegacyProtoParameters() {
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(TestOnlyKeyTemplate());
  if (!serialization.ok()) return serialization.status();

  return LegacyProtoParameters(*serialization);
}

// Valid parameters, which are serialized to a key format that the
// `TestOnlyKeyTypeManager` rejects (with a key size of 0).
class ProhibitedTestOnlyParameters : public Parameters {
 public:
  bool HasIdRequirement() const override { return true; }

  bool operator==(const Parameters& other) const override {
    return dynamic_cast<const ProhibitedTestOnlyParameters*>(&other) != nullptr;
  }

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<ProhibitedTestOnlyParameters>(*this);
  }
};

absl::StatusOr<ProtoParametersSerialization> SerializeProhibitedParameters(
    ProhibitedTestOnlyParameters parameters) {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(0);
  return ProtoParametersSerialization::Create(kTestOnlyKeyTypeUrl,
                                              OutputPrefixTypeTP::kTink,
                                              key_format.SerializeAsString());
}

absl::Status RegisterProhibitedParametersSerializer() {
  static auto* serializer =
      new ParametersSerializerImpl<ProhibitedTestOnlyParameters,
                                   ProtoParametersSerialization>(
          kTestOnlyKeyTypeUrl, SerializeProhibitedParameters);
  return MutableSerializationRegistry::GlobalInstance()
      .RegisterParametersSerializer(serializer);
}

TEST(KeysetHandleBuilderEntryTest, Status) {
  absl::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetStatus(KeyStatus::kEnabled);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kEnabled);

  entry.SetStatus(KeyStatus::kDisabled);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kDisabled);

  entry.SetStatus(KeyStatus::kDestroyed);
  EXPECT_THAT(entry.GetStatus(), KeyStatus::kDestroyed);
}

TEST(KeysetHandleBuilderEntryTest, IdStrategy) {
  absl::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetFixedId(123);
  EXPECT_THAT(entry.GetKeyIdStrategyEnum(), KeyIdStrategyEnum::kFixedId);
  EXPECT_THAT(entry.GetKeyIdStrategy().strategy, KeyIdStrategyEnum::kFixedId);
  EXPECT_THAT(entry.GetKeyIdStrategy().id_requirement, 123);
  EXPECT_THAT(entry.GetKeyIdRequirement(), 123);

  entry.SetRandomId();
  EXPECT_THAT(entry.GetKeyIdStrategyEnum(), KeyIdStrategyEnum::kRandomId);
  EXPECT_THAT(entry.GetKeyIdStrategy().strategy, KeyIdStrategyEnum::kRandomId);
  EXPECT_THAT(entry.GetKeyIdStrategy().id_requirement, std::nullopt);
  EXPECT_THAT(entry.GetKeyIdRequirement(), std::nullopt);
}

TEST(KeysetHandleBuilderEntryTest, Primary) {
  absl::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<LegacyProtoParameters>(*parameters));

  entry.SetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsTrue());

  entry.UnsetPrimary();
  EXPECT_THAT(entry.IsPrimary(), IsFalse());
}

class CreateKeysetKeyTestGlobalRegistry : public Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    std::make_unique<TestOnlyKeyTypeManager>(),
                    /*new_key_allowed=*/true),
                IsOk());
    ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  }
};

TEST_F(CreateKeysetKeyTestGlobalRegistry, CreateKeysetKeyFromParameters) {
  absl::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<LegacyProtoParameters>(*parameters));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  absl::StatusOr<util::SecretProto<Keyset::Key>> keyset_key =
      entry.CreateKeysetKey(/*id=*/123, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_key, IsOk());

  EXPECT_THAT((*keyset_key)->status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT((*keyset_key)->key_id(), Eq(123));
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      parameters->Serialization().GetKeyTemplate();
  EXPECT_THAT(
      (*keyset_key)->output_prefix_type(),
      Eq(static_cast<OutputPrefixType>(key_template.output_prefix_type())));
  EXPECT_THAT((*keyset_key)->key_data().type_url(),
              Eq(key_template.type_url()));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry,
       CreateKeysetKeyFromParametersWithDifferentKeyId) {
  absl::StatusOr<LegacyProtoParameters> parameters =
      CreateLegacyProtoParameters();
  ASSERT_THAT(parameters, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<LegacyProtoParameters>(*parameters));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  absl::StatusOr<util::SecretProto<Keyset::Key>> keyset_key =
      entry.CreateKeysetKey(/*id=*/456, KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateKeysetKeyCustomConfigTest,
     CreateKeysetKeyFromParametersCustomConfig) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());

  absl::StatusOr<TestOnlyParameters> params =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  ParametersEntry entry =
      ParametersEntry(std::make_unique<TestOnlyParameters>(*params));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);

  KeyGenConfiguration key_creator_config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
          CreateTestOnlyKey, key_creator_config),
      IsOk());

  KeyGenConfiguration key_manager_config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyTypeManager(
          std::make_unique<TestOnlyKeyTypeManager>(), key_manager_config),
      IsOk());

  absl::StatusOr<util::SecretProto<Keyset::Key>> key_from_creator_fn =
      entry.CreateKeysetKey(/*id=*/123, key_creator_config);
  ASSERT_THAT(key_from_creator_fn, IsOk());

  EXPECT_THAT((*key_from_creator_fn)->status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT((*key_from_creator_fn)->key_id(), Eq(123));
  EXPECT_THAT((*key_from_creator_fn)->output_prefix_type(),
              Eq(OutputPrefixType::TINK));
  EXPECT_THAT((*key_from_creator_fn)->key_data().type_url(),
              Eq(kTestOnlyKeyTypeUrl));

  // The keyset key created from the key manager should be the same as the one
  // created from the key creator.
  absl::StatusOr<util::SecretProto<Keyset::Key>> key_from_manager =
      entry.CreateKeysetKey(/*id=*/123, key_manager_config);
  ASSERT_THAT(key_from_manager, IsOk());

  EXPECT_THAT((*key_from_manager)->status(),
              Eq((*key_from_creator_fn)->status()));
  EXPECT_THAT((*key_from_manager)->key_id(),
              Eq((*key_from_creator_fn)->key_id()));
  EXPECT_THAT((*key_from_manager)->output_prefix_type(),
              Eq((*key_from_creator_fn)->output_prefix_type()));
  EXPECT_THAT((*key_from_manager)->key_data().type_url(),
              Eq((*key_from_creator_fn)->key_data().type_url()));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry, CreateKeysetKeyFromKey) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(std::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  absl::StatusOr<util::SecretProto<Keyset::Key>> keyset_key =
      entry.CreateKeysetKey(/*id=*/123, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(keyset_key, IsOk());

  EXPECT_THAT((*keyset_key)->status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT((*keyset_key)->key_id(), Eq(123));
  EXPECT_THAT((*keyset_key)->output_prefix_type(), OutputPrefixType::TINK);
  EXPECT_THAT((*keyset_key)->key_data().type_url(), Eq("type_url"));
  EXPECT_THAT((*keyset_key)->key_data().key_material_type(),
              Eq(KeyData::SYMMETRIC));
  EXPECT_THAT((*keyset_key)->key_data().value(), Eq("serialized_key"));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry,
       CreateKeysetKeyFromKeyWithDifferentEntryKeyId) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(std::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  entry.SetFixedId(123);
  absl::StatusOr<util::SecretProto<Keyset::Key>> keyset_key =
      entry.CreateKeysetKey(/*id=*/456, KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry,
       CreateKeysetKeyFromKeyWithDifferentSerializationKeyId) {
  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization.status(), IsOk());

  absl::StatusOr<LegacyProtoKey> key =
      LegacyProtoKey::Create(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());

  KeyEntry entry = KeyEntry(std::make_unique<LegacyProtoKey>(*key));
  entry.SetStatus(KeyStatus::kEnabled);
  absl::StatusOr<util::SecretProto<Keyset::Key>> keyset_key =
      entry.CreateKeysetKey(/*id=*/456, KeyGenConfigGlobalRegistry());
  EXPECT_THAT(keyset_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry, CreateKeysetFromNonLegacyParameters) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());
}

TEST_F(CreateKeysetKeyTestGlobalRegistry,
       CreateKeysetWithAllowedParametersProhibitedByKeyManager) {
  ASSERT_THAT(RegisterProhibitedParametersSerializer(), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              ProhibitedTestOnlyParameters(), KeyStatus::kEnabled,
              /*is_primary=*/true, /*id=*/123))
          .Build();
  ASSERT_THAT(handle.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(CreateKeysetKeyTestGlobalRegistry, CreateKeysetFromNonLegacyKey) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<TestOnlySymmetricKey> key = TestOnlySymmetricKey::Create(
      *parameters, RestrictedData(32), 123, GetPartialKeyAccess());
  ASSERT_THAT(key.status(), IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              *key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build();
  ASSERT_THAT(handle, IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
