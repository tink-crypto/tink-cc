// Copyright 2023 Google LLC
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

#include "tink/aead/internal/aes_gcm_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesGcmParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  int key_size;
  int iv_size;
  int tag_size;
  absl::optional<int> id;
  std::string output_prefix;
};

using AesGcmProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(AesGcmProtoSerializationTest, RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(AesGcmProtoSerializationTest, RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmProtoSerializationTestSuite, AesGcmProtoSerializationTest,
    Values(TestCase{AesGcmParameters::Variant::kTink, OutputPrefixType::TINK,
                    /*key_size=*/16, /*iv_size=*/12, /*tag_size=*/16,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{AesGcmParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY, /*key_size=*/16, /*iv_size=*/12,
                    /*tag_size=*/16, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{AesGcmParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    /*key_size=*/32, /*iv_size=*/12, /*tag_size=*/16,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(AesGcmProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(test_case.key_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesGcmParameters* gcm_params =
      dynamic_cast<const AesGcmParameters*>(params->get());
  ASSERT_THAT(gcm_params, NotNull());
  EXPECT_THAT(gcm_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(gcm_params->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(gcm_params->IvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(gcm_params->TagSizeInBytes(), Eq(test_case.tag_size));
}

TEST_P(AesGcmProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  AesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(test_case.key_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesGcmParameters* gcm_params =
      dynamic_cast<const AesGcmParameters*>(params->get());
  ASSERT_THAT(gcm_params, NotNull());
  EXPECT_THAT(gcm_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(gcm_params->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(gcm_params->IvSizeInBytes(), Eq(test_case.iv_size));
  EXPECT_THAT(gcm_params->TagSizeInBytes(), Eq(test_case.tag_size));
}

TEST_F(AesGcmProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(16);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(16);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, ParseParametersWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  key_format_proto.set_key_size(16);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url,
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  AesGcmKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
}

TEST_P(AesGcmProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url,
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));
  AesGcmKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
}

TEST_F(AesGcmProtoSerializationTest, SerializeParametersWithDisallowedIvSize) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(14)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, SerializeParametersWithDisallowedTagSize) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(14)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmProtoSerializationTest, ParseKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<AesGcmParameters> expected_parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<AesGcmKey> expected_key = AesGcmKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(AesGcmProtoSerializationTest, ParseKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<AesGcmParameters> expected_parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<AesGcmKey> expected_key = AesGcmKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(AesGcmProtoSerializationTest, ParseLegacyKeyAsCrunchy) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::LEGACY, /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  const AesGcmKey* aes_gcm_key = dynamic_cast<const AesGcmKey*>(key->get());
  ASSERT_THAT(aes_gcm_key, NotNull());
  EXPECT_THAT(aes_gcm_key->GetParameters().GetVariant(),
              Eq(AesGcmParameters::Variant::kCrunchy));
}

TEST_F(AesGcmProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, ParseKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesGcmKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesGcmKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
}

TEST_P(AesGcmProtoSerializationTest, SerializeKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesGcmKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
}

TEST_F(AesGcmProtoSerializationTest, SerializeKeyWithDisallowedIvSize) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(14)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, SerializeKeyWithDisallowedTagSize) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(14)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmProtoSerializationTest, SerializeKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesGcmProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  absl::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key, absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
