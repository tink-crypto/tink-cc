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

#include "tink/jwt/internal/jwt_ecdsa_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey";

struct TestCase {
  JwtEcdsaParameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtEcdsaParameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeEnum output_prefix_type;
  JwtEcdsaParameters::Algorithm algorithm;
  JwtEcdsaAlgorithm proto_algorithm;
  subtle::EllipticCurveType curve;
  absl::optional<std::string> kid;
  absl::optional<int> id;
  std::string output_prefix;
};

using JwtEcdsaProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(JwtEcdsaProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  EXPECT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());
  EXPECT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(JwtEcdsaProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  EXPECT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  EXPECT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtEcdsaProtoSerializationTestSuite, JwtEcdsaProtoSerializationTest,
    Values(
        TestCase{
            /*strategy=*/JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
            /*expected_parameters_strategy=*/
            JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
            OutputPrefixTypeEnum::kTink, JwtEcdsaParameters::Algorithm::kEs256,
            JwtEcdsaAlgorithm::ES256, subtle::EllipticCurveType::NIST_P256,
            /*kid=*/"AgMEAA", /*id=*/0x02030400,
            /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{/*strategy=*/JwtEcdsaParameters::KidStrategy::kIgnored,
                 /*expected_parameters_strategy=*/
                 JwtEcdsaParameters::KidStrategy::kIgnored,
                 OutputPrefixTypeEnum::kRaw,
                 JwtEcdsaParameters::Algorithm::kEs384,
                 JwtEcdsaAlgorithm::ES384, subtle::EllipticCurveType::NIST_P384,
                 /*kid=*/absl::nullopt, /*id=*/absl::nullopt,
                 /*output_prefix=*/""},
        TestCase{/*strategy=*/JwtEcdsaParameters::KidStrategy::kCustom,
                 /*expected_parameters_strategy=*/
                 JwtEcdsaParameters::KidStrategy::kIgnored,
                 OutputPrefixTypeEnum::kRaw,
                 JwtEcdsaParameters::Algorithm::kEs512,
                 JwtEcdsaAlgorithm::ES512, subtle::EllipticCurveType::NIST_P521,
                 /*kid=*/"custom_kid", /*id=*/absl::nullopt,
                 /*output_prefix=*/""}));

TEST_P(JwtEcdsaProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           test_case.output_prefix_type,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  absl::StatusOr<JwtEcdsaParameters> expected = JwtEcdsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_P(JwtEcdsaProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           test_case.output_prefix_type,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  absl::StatusOr<JwtEcdsaParameters> expected = JwtEcdsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(JwtEcdsaProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseParametersWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_algorithm(JwtEcdsaAlgorithm::ES256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           OutputPrefixTypeEnum::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseParametersWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           OutputPrefixTypeEnum::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtEcdsaAlgorithm")));
}

using JwtEcdsaParsePrefixTest = TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(JwtEcdsaParsePrefixTestSuite, JwtEcdsaParsePrefixTest,
                         Values(OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(JwtEcdsaParsePrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtEcdsaAlgorithm::ES256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           invalid_output_prefix_type,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtEcdsaKeyFormat")));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateTP& key_template = proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));
  JwtEcdsaKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtEcdsaParameters> parameters = JwtEcdsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateTP& key_template = proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));
  JwtEcdsaKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_F(JwtEcdsaProtoSerializationTest, SerializeParametersWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to serialize "
                                 "JwtEcdsaParameters::KidStrategy::kCustom")));
}

TEST_P(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtEcdsaParameters> expected_parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*expected_parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_P(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtEcdsaParameters> expected_parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder public_key_builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> expected_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseTinkPublicKeyWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtEcdsaPublicKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Parsing JwtEcdsaPublicKey failed: only version 0 is accepted")));
}

TEST_P(JwtEcdsaParsePrefixTest, ParsePublicKeyWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtEcdsaKeyFormat")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtEcdsaAlgorithm")));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtEcdsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.x(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_x)));
  EXPECT_THAT(proto_key.y(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_y)));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
  }
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder public_key_builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtEcdsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.x(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_x)));
  EXPECT_THAT(proto_key.y(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_y)));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
  }
}

TEST_P(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtEcdsaParameters> expected_parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*expected_parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> expected_private_key =
      JwtEcdsaPrivateKey::Create(
          *expected_public_key,
          RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                               InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_P(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(*test_case.kid);
  }

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  absl::StatusOr<JwtEcdsaParameters> expected_parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder public_key_builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> expected_public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> expected_private_key =
      JwtEcdsaPrivateKey::Create(
          *expected_public_key,
          RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                               InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_F(JwtEcdsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(1);  // Invalid version number.
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsing JwtEcdsaPrivateKey failed: only "
                                 "version 0 is accepted")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithoutPublicKey) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtEcdsaParsePrefixTest, ParsePrivateKeyWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtEcdsaKeyFormat")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtEcdsaAlgorithm")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePrivateKeyWithoutSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtEcdsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(),
              Eq(absl::StrCat(std::string("\x00", 1),
                              util::SecretDataAsStringView(ec_key->priv))));
  EXPECT_THAT(proto_key.public_key().x(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_x)));
  EXPECT_THAT(proto_key.public_key().y(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_y)));
  EXPECT_THAT(proto_key.public_key().algorithm(),
              Eq(test_case.proto_algorithm));
  ASSERT_THAT(
      proto_key.public_key().has_custom_kid(),
      Eq(test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.public_key().custom_kid().value(),
                Eq(*public_key->GetKid()));
  }
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder public_key_builder =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(*test_case.kid);
  }
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtEcdsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(),
              Eq(absl::StrCat(std::string("\x00", 1),
                              util::SecretDataAsStringView(ec_key->priv))));
  EXPECT_THAT(proto_key.public_key().x(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_x)));
  EXPECT_THAT(proto_key.public_key().y(),
              Eq(absl::StrCat(std::string("\x00", 1), ec_key->pub_y)));
  EXPECT_THAT(proto_key.public_key().algorithm(),
              Eq(test_case.proto_algorithm));
  ASSERT_THAT(
      proto_key.public_key().has_custom_kid(),
      Eq(test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom));
  if (test_case.strategy == JwtEcdsaParameters::KidStrategy::kCustom) {
    EXPECT_THAT(proto_key.public_key().custom_kid().value(),
                Eq(*public_key->GetKid()));
  }
}

TEST_F(JwtEcdsaProtoSerializationTest,
       SerializePrivateKeyWithoutSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtEcdsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<EcKey> ec_key = NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*private_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
