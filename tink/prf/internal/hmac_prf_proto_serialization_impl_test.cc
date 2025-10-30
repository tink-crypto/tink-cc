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

#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
#include "tink/prf/hmac_prf_key.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacPrfKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacPrfKey";

struct TestCase {
  int key_size;
  HmacPrfParameters::HashType hash_type;
  HashType proto_hash_type;
};

using HmacPrfProtoSerializationTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    HmacPrfParametersCreateTestSuite, HmacPrfProtoSerializationTest,
    Values(TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha1,
                    HashType::SHA1},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha224,
                    HashType::SHA224},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha256,
                    HashType::SHA256},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha384,
                    HashType::SHA384},
           TestCase{/*key_size=*/32, HmacPrfParameters::HashType::kSha512,
                    HashType::SHA512}));

TEST_F(HmacPrfProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(HmacPrfProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

TEST_P(HmacPrfProtoSerializationTest, ParseParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  TestCase test_case = GetParam();

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(test_case.key_size);
  proto_key_format.mutable_params()->set_hash(test_case.proto_hash_type);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(), IsFalse());

  absl::StatusOr<HmacPrfParameters> expected_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(expected_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_P(HmacPrfProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(test_case.key_size);
  proto_key_format.mutable_params()->set_hash(test_case.proto_hash_type);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(), IsFalse());

  absl::StatusOr<HmacPrfParameters> expected_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(expected_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(HmacPrfProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeEnum::kRaw,
                                           "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse HmacPrfKeyFormat proto")));
}

using HmacPrfParsePrefixTest = TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(HmacPrfParsePrefixTestSuite, HmacPrfParsePrefixTest,
                         Values(OutputPrefixTypeEnum::kTink,
                                OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(HmacPrfParsePrefixTest, ParseParametersWithInvalidPrefixFails) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, invalid_output_prefix_type,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Output prefix type must be RAW for HmacPrfParameters")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(1);  // invalid version
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseParametersWithUnknownHashTypeFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HmacPrfKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.set_version(0);
  key_format_proto.mutable_params()->set_hash(HashType::UNKNOWN_HASH);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine HashType")));
}

TEST_P(HmacPrfProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  TestCase test_case = GetParam();
  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(internal::OutputPrefixTypeEnum::kRaw));

  HmacPrfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_P(HmacPrfProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();
  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(internal::OutputPrefixTypeEnum::kRaw));

  HmacPrfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_P(HmacPrfProtoSerializationTest, ParseKeyWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::HmacPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(test_case.proto_hash_type);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(), IsFalse());

  absl::StatusOr<HmacPrfParameters> expected_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HmacPrfKey> expected_key = HmacPrfKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(HmacPrfProtoSerializationTest, ParseKeyWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::HmacPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(test_case.proto_hash_type);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(), IsFalse());

  absl::StatusOr<HmacPrfParameters> expected_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HmacPrfKey> expected_key = HmacPrfKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(HmacPrfProtoSerializationTest, ParseKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse HmacPrfKey proto")));
}

TEST_P(HmacPrfParsePrefixTest, ParseKeyWithInvalidPrefixFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Output prefix type must be RAW for HmacPrfKey")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HmacPrfKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(HmacPrfProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HmacPrfKey> key = HmacPrfKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(OutputPrefixTypeEnum::kRaw));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::HmacPrfKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_P(HmacPrfProtoSerializationTest, SerializeKeyWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HmacPrfKey> key = HmacPrfKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(OutputPrefixTypeEnum::kRaw));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::HmacPrfKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.params().hash(), Eq(test_case.proto_hash_type));
}

TEST_F(HmacPrfProtoSerializationTest, SerializeKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHmacPrfProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  absl::StatusOr<HmacPrfParameters> parameters = HmacPrfParameters::Create(
      /*key_size_in_bytes=*/16, HmacPrfParameters::HashType::kSha256);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HmacPrfKey> key = HmacPrfKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
