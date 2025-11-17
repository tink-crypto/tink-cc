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

#include "tink/jwt/internal/jwt_hmac_proto_serialization_impl.h"

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
#include "tink/jwt/jwt_hmac_key.h"
#include "tink/jwt/jwt_hmac_parameters.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtHmacAlgorithm;
using ::google::crypto::tink::JwtHmacKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtHmacKey";

struct TestCase {
  JwtHmacParameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtHmacParameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeEnum output_prefix_type;
  JwtHmacParameters::Algorithm algorithm;
  JwtHmacAlgorithm proto_algorithm;
  int key_size;
  absl::optional<std::string> kid;
  absl::optional<int> id;
  std::string output_prefix;
};

using JwtHmacProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(JwtHmacProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  EXPECT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
  EXPECT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(JwtHmacProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  EXPECT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  EXPECT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtHmacProtoSerializationTestSuite, JwtHmacProtoSerializationTest,
    Values(TestCase{
               /*strategy=*/JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
               /*expected_parameters_strategy=*/
               JwtHmacParameters::KidStrategy::kBase64EncodedKeyId,
               OutputPrefixTypeEnum::kTink,
               JwtHmacParameters::Algorithm::kHs256, JwtHmacAlgorithm::HS256,
               /*key_size=*/16, /*kid=*/"AgMEAA",
               /*id=*/0x02030400,
               /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*strategy=*/JwtHmacParameters::KidStrategy::kIgnored,
                    /*expected_parameters_strategy=*/
                    JwtHmacParameters::KidStrategy::kIgnored,
                    OutputPrefixTypeEnum::kRaw,
                    JwtHmacParameters::Algorithm::kHs384,
                    JwtHmacAlgorithm::HS384,
                    /*key_size=*/32, /*kid=*/absl::nullopt,
                    /*id=*/absl::nullopt, /*output_prefix=*/""},
           TestCase{/*strategy=*/JwtHmacParameters::KidStrategy::kCustom,
                    /*expected_parameters_strategy=*/
                    JwtHmacParameters::KidStrategy::kIgnored,
                    OutputPrefixTypeEnum::kRaw,
                    JwtHmacParameters::Algorithm::kHs512,
                    JwtHmacAlgorithm::HS512,
                    /*key_size=*/32, /*kid=*/"custom_kid",
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(JwtHmacProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(test_case.key_size);
  format.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  absl::StatusOr<JwtHmacParameters> expected = JwtHmacParameters::Create(
      test_case.key_size, test_case.expected_parameters_strategy,
      test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_P(JwtHmacProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(test_case.key_size);
  format.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  absl::StatusOr<JwtHmacParameters> expected = JwtHmacParameters::Create(
      test_case.key_size, test_case.expected_parameters_strategy,
      test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeEnum::kRaw,
                                           "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtHmacKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeEnum::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseParametersWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeEnum::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtHmacAlgorithm")));
}

using JwtHmacParsePrefixTest = TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(JwtHmacParsePrefixTestSuite, JwtHmacParsePrefixTest,
                         Values(OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(JwtHmacParsePrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtHmacKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  format.set_algorithm(JwtHmacAlgorithm::HS256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, invalid_output_prefix_type,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtHmacKeyFormat")));
}

TEST_P(JwtHmacProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.expected_parameters_strategy,
      test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateTP& key_template = proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));
  JwtHmacKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_P(JwtHmacProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.expected_parameters_strategy,
      test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateTP& key_template = proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));
  JwtHmacKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_F(JwtHmacProtoSerializationTest, SerializeParametersWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kCustom,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(
      serialization.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Unable to serialize JwtHmacParameters::KidStrategy::kCustom")));
}

TEST_P(JwtHmacProtoSerializationTest, ParseKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_key_value(raw_key_bytes);
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtHmacParameters> expected_parameters =
      JwtHmacParameters::Create(test_case.key_size, test_case.strategy,
                                test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*expected_parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtHmacKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_P(JwtHmacProtoSerializationTest, ParseKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_key_value(raw_key_bytes);
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtHmacParameters> expected_parameters =
      JwtHmacParameters::Create(test_case.key_size, test_case.strategy,
                                test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  JwtHmacKey::Builder key_builder =
      JwtHmacKey::Builder()
          .SetParameters(*expected_parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtHmacKey> expected_key =
      key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtHmacProtoSerializationTest, ParseTinkKeyWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtHmacKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
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
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Parsing JwtHmacKey failed: only version 0 is accepted")));
}

TEST_P(JwtHmacParsePrefixTest, ParseKeyWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtHmacKeyFormat")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS_UNKNOWN);
  key_proto.set_key_value(raw_key_bytes);
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
                       HasSubstr("Could not determine JwtHmacAlgorithm")));
}

TEST_F(JwtHmacProtoSerializationTest, ParseKeyWithoutSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::JwtHmacKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtHmacAlgorithm::HS256);
  key_proto.set_key_value(raw_key_bytes);
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtHmacProtoSerializationTest, SerializeKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  JwtHmacKey::Builder builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtHmacKey> key = builder.Build(GetPartialKeyAccess());
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
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtHmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtHmacParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
  }
}

TEST_P(JwtHmacProtoSerializationTest, SerializeKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      test_case.key_size, test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  JwtHmacKey::Builder key_builder =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()));
  if (test_case.id.has_value()) {
    key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtHmacKey> key = key_builder.Build(GetPartialKeyAccess());
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
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtHmacKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtHmacParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtHmacParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
  }
}

TEST_F(JwtHmacProtoSerializationTest, SerializeKeyWithoutSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtHmacProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtHmacParameters> parameters = JwtHmacParameters::Create(
      /*key_size_in_bytes=*/32, JwtHmacParameters::KidStrategy::kIgnored,
      JwtHmacParameters::Algorithm::kHs256);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<JwtHmacKey> key =
      JwtHmacKey::Builder()
          .SetParameters(*parameters)
          .SetKeyBytes(
              RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
