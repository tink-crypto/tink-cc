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

#include "tink/jwt/internal/jwt_rsa_ssa_pkcs1_proto_serialization_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct KeyValues {
  std::string n;
  std::string e;
  std::string p;
  std::string q;
  std::string dp;
  std::string dq;
  std::string d;
  std::string q_inv;
};

const absl::NoDestructor<KeyValues> kKeyValues([]() {
  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();
  return KeyValues{vector.n,  vector.e,  vector.p, vector.q,
                   vector.dp, vector.dq, vector.d, vector.q_inv};
}());

struct TestCase {
  JwtRsaSsaPkcs1Parameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtRsaSsaPkcs1Parameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeTP output_prefix_type;
  JwtRsaSsaPkcs1Parameters::Algorithm algorithm;
  JwtRsaSsaPkcs1Algorithm proto_algorithm;
  KeyValues key_values;
  absl::optional<std::string> kid;
  absl::optional<int> id;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537
constexpr int kModulusSizeInBits = 2048;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";

using JwtRsaSsaPkcs1ProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPkcs1ProtoSerializationTestSuite,
    JwtRsaSsaPkcs1ProtoSerializationTest,
    Values(TestCase{/*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::
                        kBase64EncodedKeyId,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
                    OutputPrefixTypeTP::kTink,
                    JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                    JwtRsaSsaPkcs1Algorithm::RS256,
                    /*key_values=*/*kKeyValues,
                    /*kid=*/"AgMEAA", /*id=*/0x02030400},
           TestCase{
               /*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
               /*expected_parameters_strategy=*/
               JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
               OutputPrefixTypeTP::kRaw,
               JwtRsaSsaPkcs1Parameters::Algorithm::kRs384,
               JwtRsaSsaPkcs1Algorithm::RS384,
               /*key_values=*/*kKeyValues,
               /*kid=*/std::nullopt,
               /*id=*/std::nullopt},
           TestCase{/*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                    OutputPrefixTypeTP::kRaw,
                    JwtRsaSsaPkcs1Parameters::Algorithm::kRs512,
                    JwtRsaSsaPkcs1Algorithm::RS512,
                    /*key_values=*/*kKeyValues,
                    /*kid=*/"custom_kid",
                    /*id=*/std::nullopt}));

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersSucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(kModulusSizeInBits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<const JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersSucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(kModulusSizeInBits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<const JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeTP::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(1);  // invalid version number
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeTP::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

using JwtRsaSsaPkcs1ParseInvalidPrefixTest = TestWithParam<OutputPrefixTypeTP>;

INSTANTIATE_TEST_SUITE_P(JwtRsaSsaPkcs1ParseInvalidPrefixTestSuite,
                         JwtRsaSsaPkcs1ParseInvalidPrefixTest,
                         Values(OutputPrefixTypeTP::kCrunchy,
                                OutputPrefixTypeTP::kLegacy,
                                OutputPrefixTypeTP::kUnknownPrefix));

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeTP invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, invalid_output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithUnknownAlgorithmFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeTP::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(
      registry.ParseParameters(*serialization).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine JwtRsaSsaPkcs1Algorithm")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializeParametersSucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
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
  EXPECT_THAT(
      key_template.output_prefix_type(),
      Eq(static_cast<OutputPrefixTypeTP>(test_case.output_prefix_type)));
  JwtRsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  EXPECT_THAT(key_format.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(key_format.modulus_size_in_bits(), Eq(kModulusSizeInBits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializeParametersSucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
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
  EXPECT_THAT(
      key_template.output_prefix_type(),
      Eq(static_cast<OutputPrefixTypeTP>(test_case.output_prefix_type)));
  JwtRsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  EXPECT_THAT(key_format.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(key_format.modulus_size_in_bits(), Eq(kModulusSizeInBits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializeParametersWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(
      serialization.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unable to serialize "
                         "JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = test_case.key_values;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = test_case.key_values;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder public_key_builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> expected_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;
  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseTinkPublicKeyWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;
  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtRsaSsaPkcs1PublicKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest,
       ParsePublicKeyWithInvalidPrefixFails) {
  OutputPrefixTypeTP invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidAlgorithmFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPkcs1KeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPublic,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(
      parsed_key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine JwtRsaSsaPkcs1Algorithm")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializePublicKeySucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = test_case.key_values;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializePublicKeySucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();
  KeyValues key_values = test_case.key_values;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder public_key_builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(
      proto_key.has_custom_kid(),
      Eq(test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = test_case.key_values;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> expected_private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetPrimeP(RestrictedData(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = test_case.key_values;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder public_key_builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> expected_public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> expected_private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetPrimeP(RestrictedData(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(1);  // invalid version number
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(1);  // invalid version number
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 public keys are accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithoutPublicKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest,
       ParsePrivateKeyWithInvalidPrefixFails) {
  OutputPrefixTypeTP invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);
  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(1);  // invalid version number
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kAsymmetricPrivate,
                                    OutputPrefixTypeTP::kRaw,
                                    /*id_requirement=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializePrivateKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = test_case.key_values;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.p(), Eq(key_values.p));
  EXPECT_THAT(proto_key.q(), Eq(key_values.q));
  EXPECT_THAT(proto_key.dp(), Eq(key_values.dp));
  EXPECT_THAT(proto_key.dq(), Eq(key_values.dq));
  EXPECT_THAT(proto_key.d(), Eq(key_values.d));
  EXPECT_THAT(proto_key.crt(), Eq(key_values.q_inv));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.public_key().e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.public_key().algorithm(),
              Eq(test_case.proto_algorithm));
  ASSERT_THAT(
      proto_key.public_key().has_custom_kid(),
      Eq(test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializePrivateKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = test_case.key_values;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPkcs1PublicKey::Builder public_key_builder =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.p(), Eq(key_values.p));
  EXPECT_THAT(proto_key.q(), Eq(key_values.q));
  EXPECT_THAT(proto_key.dp(), Eq(key_values.dp));
  EXPECT_THAT(proto_key.dq(), Eq(key_values.dq));
  EXPECT_THAT(proto_key.d(), Eq(key_values.d));
  EXPECT_THAT(proto_key.crt(), Eq(key_values.q_inv));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.public_key().e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.public_key().algorithm(),
              Eq(test_case.proto_algorithm));
  ASSERT_THAT(
      proto_key.public_key().has_custom_kid(),
      Eq(test_case.strategy == JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializePrivateKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPkcs1ProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = *kKeyValues;

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*private_key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
