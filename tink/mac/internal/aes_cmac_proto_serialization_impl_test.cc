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

#include "tink/mac/internal/aes_cmac_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/testing/equals_proto_key_serialization.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/key.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_testing::EqualsProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesCmacParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  int key_size;
  int tag_size;
  int total_size;
  absl::optional<int> id;
  std::string output_prefix;
};

using AesCmacProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(AesCmacProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(AesCmacProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesCmacProtoSerializationTestSuite, AesCmacProtoSerializationTest,
    Values(TestCase{AesCmacParameters::Variant::kTink, OutputPrefixType::TINK,
                    /*key_size=*/16, /*tag_size=*/10, /*total_size=*/15,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{AesCmacParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY, /*key_size=*/16,
                    /*tag_size=*/12, /*total_size=*/17, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{AesCmacParameters::Variant::kLegacy,
                    OutputPrefixType::LEGACY, /*key_size=*/32,
                    /*cryptographic_tag_size=*/14, /*total_tag_size=*/19,
                    /*id=*/0x01020304,
                    /*output_prefix=*/std::string("\x00\x01\x02\x03\x04", 5)},
           TestCase{AesCmacParameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW, /*key_size=*/32,
                    /*cryptographic_tag_size=*/16, /*total_tag_size=*/16,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(AesCmacProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesCmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(test_case.key_size);
  key_format_proto.mutable_params()->set_tag_size(test_case.tag_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesCmacParameters* cmac_params =
      dynamic_cast<const AesCmacParameters*>(params->get());
  ASSERT_THAT(cmac_params, NotNull());
  EXPECT_THAT(cmac_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cmac_params->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(cmac_params->CryptographicTagSizeInBytes(),
              Eq(test_case.tag_size));
  EXPECT_THAT(cmac_params->TotalTagSizeInBytes(), Eq(test_case.total_size));
}

TEST_P(AesCmacProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  AesCmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(test_case.key_size);
  key_format_proto.mutable_params()->set_tag_size(test_case.tag_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesCmacParameters* cmac_params =
      dynamic_cast<const AesCmacParameters*>(params->get());
  ASSERT_THAT(cmac_params, NotNull());
  EXPECT_THAT(cmac_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cmac_params->KeySizeInBytes(), Eq(test_case.key_size));
  EXPECT_THAT(cmac_params->CryptographicTagSizeInBytes(),
              Eq(test_case.tag_size));
  EXPECT_THAT(cmac_params->TotalTagSizeInBytes(), Eq(test_case.total_size));
}

TEST_F(AesCmacProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesCmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.mutable_params()->set_tag_size(10);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCmacProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesCmacKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.mutable_params()->set_tag_size(10);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCmacProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      test_case.key_size, test_case.tag_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesCmacKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_THAT(key_format.key_size(), Eq(test_case.key_size));
  ASSERT_THAT(key_format.params().tag_size(), Eq(test_case.tag_size));
}

TEST_P(AesCmacProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      test_case.key_size, test_case.tag_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesCmacKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_THAT(key_format.key_size(), Eq(test_case.key_size));
  ASSERT_THAT(key_format.params().tag_size(), Eq(test_case.tag_size));
}

TEST_P(AesCmacProtoSerializationTest, ParseKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesCmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(test_case.tag_size);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  const AesCmacKey* cmac_key = dynamic_cast<const AesCmacKey*>(key->get());
  ASSERT_THAT(cmac_key, NotNull());
  absl::StatusOr<RestrictedData> parsed_key =
      cmac_key->GetKeyBytes(GetPartialKeyAccess());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(parsed_key->GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(raw_key_bytes));
  EXPECT_THAT(cmac_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(cmac_key->GetParameters().GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cmac_key->GetParameters().KeySizeInBytes(),
              Eq(test_case.key_size));
  EXPECT_THAT(cmac_key->GetParameters().CryptographicTagSizeInBytes(),
              Eq(test_case.tag_size));
  EXPECT_THAT(cmac_key->GetParameters().TotalTagSizeInBytes(),
              test_case.total_size);
  EXPECT_THAT(cmac_key->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
}

TEST_P(AesCmacProtoSerializationTest, ParseKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesCmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(test_case.tag_size);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey", serialized_key,
          KeyData::SYMMETRIC, test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  const AesCmacKey* cmac_key = dynamic_cast<const AesCmacKey*>(key->get());
  ASSERT_THAT(cmac_key, NotNull());
  absl::StatusOr<RestrictedData> parsed_key =
      cmac_key->GetKeyBytes(GetPartialKeyAccess());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(parsed_key->GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(raw_key_bytes));
  EXPECT_THAT(cmac_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(cmac_key->GetParameters().GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cmac_key->GetParameters().KeySizeInBytes(),
              Eq(test_case.key_size));
  EXPECT_THAT(cmac_key->GetParameters().CryptographicTagSizeInBytes(),
              Eq(test_case.tag_size));
  EXPECT_THAT(cmac_key->GetParameters().TotalTagSizeInBytes(),
              test_case.total_size);
  EXPECT_THAT(cmac_key->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
}

TEST_F(AesCmacProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCmacProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(10);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, absl::nullopt);
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCmacProtoSerializationTest, ParseKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesCmacKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_tag_size(10);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesCmacKey", serialized_key,
          KeyData::SYMMETRIC, OutputPrefixType::TINK,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCmacProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      test_case.key_size, test_case.tag_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesCmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
  EXPECT_THAT(proto_key.params().tag_size(), Eq(test_case.tag_size));
}

TEST_P(AesCmacProtoSerializationTest, SerializeKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      test_case.key_size, test_case.tag_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesCmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
  EXPECT_THAT(proto_key.params().tag_size(), Eq(test_case.tag_size));
}

TEST_F(AesCmacProtoSerializationTest, SerializeKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesCmacParameters> parameters = AesCmacParameters::Create(
      /*key_size_in_bytes=*/16, /*cryptographic_tag_size_in_bytes=*/10,
      AesCmacParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key, absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

struct KeyAndSerialization {
  KeyAndSerialization(std::shared_ptr<Key> key,
                      ProtoKeySerialization proto_key_serialization)
      : key(std::move(key)),
        proto_key_serialization(std::move(proto_key_serialization)) {}

  std::shared_ptr<Key> key;
  ProtoKeySerialization proto_key_serialization;
};

class SerializationTest : public testing::TestWithParam<KeyAndSerialization> {};
class ParseTest : public testing::TestWithParam<KeyAndSerialization> {};

TEST_P(SerializationTest, SerializesCorrectly) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *test_key.key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization.status(), IsOk());
  ProtoKeySerialization* proto_serialization =
      dynamic_cast<ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, Not(IsNull()));
  EXPECT_THAT(*proto_serialization,
              EqualsProtoKeySerialization(test_key.proto_key_serialization));
}

TEST_P(ParseTest, ParserCorrectly) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesCmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key = registry.ParseKey(
      test_key.proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_TRUE(**key == *test_key.key);
}

KeyAndSerialization CanonicalKeyAndSerialization0() {
  absl::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(16, 11, AesCmacParameters::Variant::kTink);
  CHECK_OK(parameters);

  absl::StatusOr<AesCmacKey> key = AesCmacKey::Create(
      *parameters,
      RestrictedData("16 key bytes....", InsecureSecretKeyAccess::Get()), 104,
      GetPartialKeyAccess());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.AesCmacKey",
      {FieldWithNumber(2).IsString("16 key bytes...."),
       FieldWithNumber(3).IsSubMessage({FieldWithNumber(1).IsVarint(11)})},
      KeyData::SYMMETRIC, OutputPrefixType::TINK, 104);

  return KeyAndSerialization(absl::make_unique<AesCmacKey>(*key),
                             serialization);
}

KeyAndSerialization CanonicalKeyAndSerialization1() {
  absl::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(32, 11, AesCmacParameters::Variant::kNoPrefix);
  CHECK_OK(parameters);

  absl::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*parameters,
                         RestrictedData("32 key bytes....32 key bytes....",
                                        InsecureSecretKeyAccess::Get()),
                         absl::nullopt, GetPartialKeyAccess());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.AesCmacKey",
      {FieldWithNumber(2).IsString("32 key bytes....32 key bytes...."),
       FieldWithNumber(3).IsSubMessage({FieldWithNumber(1).IsVarint(11)})},
      KeyData::SYMMETRIC, OutputPrefixType::RAW, absl::nullopt);

  return KeyAndSerialization(absl::make_unique<AesCmacKey>(*key),
                             serialization);
}

KeyAndSerialization NonCanonicalKeyAndSerialization2() {
  absl::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(32, 11, AesCmacParameters::Variant::kNoPrefix);
  CHECK_OK(parameters);

  absl::StatusOr<AesCmacKey> key =
      AesCmacKey::Create(*parameters,
                         RestrictedData("32 key bytes....32 key bytes....",
                                        InsecureSecretKeyAccess::Get()),
                         absl::nullopt, GetPartialKeyAccess());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.AesCmacKey",
      {// Add an explicit version field
       FieldWithNumber(1).IsVarint(0),
       FieldWithNumber(2).IsString("32 key bytes....32 key bytes...."),
       FieldWithNumber(3).IsSubMessage({FieldWithNumber(1).IsVarint(11)})},
      KeyData::SYMMETRIC, OutputPrefixType::RAW, absl::nullopt);

  return KeyAndSerialization(absl::make_unique<AesCmacKey>(*key),
                             serialization);
}

INSTANTIATE_TEST_SUITE_P(SerializationTest, SerializationTest,
                         testing::Values(CanonicalKeyAndSerialization0(),
                                         CanonicalKeyAndSerialization1()));

INSTANTIATE_TEST_SUITE_P(ParseTest, ParseTest,
                         testing::Values(CanonicalKeyAndSerialization0(),
                                         CanonicalKeyAndSerialization1(),
                                         NonCanonicalKeyAndSerialization2()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
