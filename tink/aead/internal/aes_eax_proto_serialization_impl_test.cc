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

#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_eax_key.h"
#include "tink/aead/aes_eax_parameters.h"
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
#include "tink/util/test_matchers.h"
#include "proto/aes_eax.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesEaxKeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kAesEaxTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesEaxKey";

struct TestCase {
  int key_size;
  int iv_size;
  AesEaxParameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

using AesEaxProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(AesEaxProtoSerializationTest, RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(AesEaxProtoSerializationTest, RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesEaxProtoSerializationTestSuite, AesEaxProtoSerializationTest,
    Values(TestCase{/*key_size=*/16, /*iv_size=*/12,
                    AesEaxParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*key_size=*/24, /*iv_size=*/12,
                    AesEaxParameters::Variant::kCrunchy,
                    OutputPrefixTypeEnum::kCrunchy, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*key_size=*/32, /*iv_size=*/16,
                    AesEaxParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(AesEaxProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesEaxKeyFormat key_format_proto;
  key_format_proto.set_key_size(test_case.key_size);
  key_format_proto.mutable_params()->set_iv_size(test_case.iv_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kAesEaxTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              Eq(test_case.id.has_value()));

  absl::StatusOr<AesEaxParameters> expected_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_P(AesEaxProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  AesEaxKeyFormat key_format_proto;
  key_format_proto.set_key_size(test_case.key_size);
  key_format_proto.mutable_params()->set_iv_size(test_case.iv_size);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kAesEaxTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              Eq(test_case.id.has_value()));

  absl::StatusOr<AesEaxParameters> expected_parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(AesEaxProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesEaxKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.mutable_params()->set_iv_size(16);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kAesEaxTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesEaxProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  AesEaxKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.mutable_params()->set_iv_size(16);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kAesEaxTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  // Tink currently restricts AES-EAX tag size to 16 bytes.
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kAesEaxTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kAesEaxTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesEaxKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().iv_size(), Eq(test_case.iv_size));
}

TEST_P(AesEaxProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  // Tink currently restricts AES-EAX tag size to 16 bytes.
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kAesEaxTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kAesEaxTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesEaxKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().iv_size(), Eq(test_case.iv_size));
}

TEST_F(AesEaxProtoSerializationTest,
       SerializeParametersWithDisallowedTagSizeFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(14)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);

  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxProtoSerializationTest, ParseKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_iv_size(test_case.iv_size);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kAesEaxTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<AesEaxParameters> expected_parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<AesEaxKey> expected_key = AesEaxKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(AesEaxProtoSerializationTest, ParseKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_iv_size(test_case.iv_size);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kAesEaxTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<AesEaxParameters> expected_parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<AesEaxKey> expected_key = AesEaxKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(AesEaxProtoSerializationTest, ParseLegacyKeyAsCrunchy) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_iv_size(16);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kAesEaxTypeUrl, serialized_key, KeyMaterialTypeEnum::kSymmetric,
          OutputPrefixTypeEnum::kLegacy, /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());

  const AesEaxKey* aes_eax_key = dynamic_cast<const AesEaxKey*>(key->get());
  ASSERT_THAT(aes_eax_key, NotNull());
  EXPECT_THAT(aes_eax_key->GetParameters().GetVariant(),
              Eq(AesEaxParameters::Variant::kCrunchy));
}

TEST_F(AesEaxProtoSerializationTest, ParseKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kAesEaxTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesEaxProtoSerializationTest, ParseKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_iv_size(16);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kAesEaxTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesEaxProtoSerializationTest, ParseKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::AesEaxKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_iv_size(16);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kAesEaxTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesEaxProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  // Tink currently restricts AES-EAX tag size to 16 bytes.
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kAesEaxTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kAesEaxTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesEaxKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.params().iv_size(), Eq(test_case.iv_size));
}

TEST_P(AesEaxProtoSerializationTest, SerializeKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  // Tink currently restricts AES-EAX tag size to 16 bytes.
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKeySizeInBytes(test_case.key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kAesEaxTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kAesEaxTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::AesEaxKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.key_value().size(), Eq(test_case.key_size));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.params().iv_size(), Eq(test_case.iv_size));
}

TEST_F(AesEaxProtoSerializationTest, SerializeKeyWithDisallowedTagSizeFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(32)
          .SetIvSizeInBytes(16)
          .SetTagSizeInBytes(12)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
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

TEST_F(AesEaxProtoSerializationTest, SerializeKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterAesEaxProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  absl::StatusOr<AesEaxKey> key = AesEaxKey::Create(
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
