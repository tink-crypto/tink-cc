// Copyright 2024 Google LLC
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

#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/legacy_kms_aead_key.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/kms_aead.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KmsAeadKey;
using ::google::crypto::tink::KmsAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsAeadKey";

const absl::string_view kKeyUri = "some://arbitrary.key.uri?q=123#xyz";

struct TestCase {
  LegacyKmsAeadParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

using LegacyKmsAeadProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(LegacyKmsAeadProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());
}

TEST_F(LegacyKmsAeadProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsAeadProtoSerializationTestSuite,
    LegacyKmsAeadProtoSerializationTest,
    Values(TestCase{LegacyKmsAeadParameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{LegacyKmsAeadParameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(LegacyKmsAeadProtoSerializationTest,
       ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const LegacyKmsAeadParameters* kms_aead_params =
      dynamic_cast<const LegacyKmsAeadParameters*>(params->get());
  ASSERT_THAT(kms_aead_params, NotNull());
  EXPECT_THAT(kms_aead_params->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(kms_aead_params->GetVariant(), Eq(test_case.variant));
}

TEST_P(LegacyKmsAeadProtoSerializationTest,
       ParseParametersWithImmutableRegistry) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const LegacyKmsAeadParameters* kms_aead_params =
      dynamic_cast<const LegacyKmsAeadParameters*>(params->get());
  ASSERT_THAT(kms_aead_params, NotNull());
  EXPECT_THAT(kms_aead_params->GetKeyUri(), Eq(kKeyUri));
  EXPECT_THAT(kms_aead_params->GetVariant(), Eq(test_case.variant));
}

TEST_F(LegacyKmsAeadProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(LegacyKmsAeadProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine LegacyKmsAeadParameters::Variant")));
}

TEST_P(LegacyKmsAeadProtoSerializationTest,
       SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<internal::ProtoParametersSerialization>(
          *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  KmsAeadKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  EXPECT_THAT(key_format.key_uri(), Eq(kKeyUri));
}

TEST_P(LegacyKmsAeadProtoSerializationTest,
       SerializeParametersWithImmutableRegistry) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<internal::ProtoParametersSerialization>(
          *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  KmsAeadKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  EXPECT_THAT(key_format.key_uri(), Eq(kKeyUri));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, ParseKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);
  KmsAeadKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = key_format_proto;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::REMOTE,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<LegacyKmsAeadParameters> expected_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<LegacyKmsAeadKey> expected_key =
      LegacyKmsAeadKey::Create(*expected_parameters, test_case.id);
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, ParseKeyWithImmutableRegistry) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);
  KmsAeadKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = key_format_proto;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::REMOTE,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<LegacyKmsAeadParameters> expected_parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<LegacyKmsAeadKey> expected_key =
      LegacyKmsAeadKey::Create(*expected_parameters, test_case.id);
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(LegacyKmsAeadProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::REMOTE, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(LegacyKmsAeadProtoSerializationTest, ParseKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KmsAeadKeyFormat key_format_proto;
  key_format_proto.set_key_uri(kKeyUri);
  KmsAeadKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  *key_proto.mutable_params() = key_format_proto;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::REMOTE, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<internal::ProtoKeySerialization>(
          *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::REMOTE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  KmsAeadKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.params().key_uri(), Eq(kKeyUri));
}

TEST_P(LegacyKmsAeadProtoSerializationTest, SerializeKeyWithImmutableRegistry) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterLegacyKmsAeadProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<LegacyKmsAeadParameters> parameters =
      LegacyKmsAeadParameters::Create(kKeyUri, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsAeadKey> key =
      LegacyKmsAeadKey::Create(*parameters, test_case.id);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<internal::ProtoKeySerialization>(
          *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::REMOTE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  KmsAeadKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.params().key_uri(), Eq(kKeyUri));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
