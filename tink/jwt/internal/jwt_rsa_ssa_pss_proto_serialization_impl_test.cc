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

#include "tink/jwt/internal/jwt_rsa_ssa_pss_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/secret_key_access_token.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPssParameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtRsaSsaPssParameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeEnum output_prefix_type;
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssAlgorithm proto_algorithm;
  int modulus_size_in_bits;
  absl::optional<std::string> kid;
  absl::optional<int> id;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537
constexpr int kModulusSizeInBits = 2048;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey";

using JwtRsaSsaPssProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPssProtoSerializationTestSuite, JwtRsaSsaPssProtoSerializationTest,
    Values(TestCase{/*strategy=*/JwtRsaSsaPssParameters::KidStrategy::
                        kBase64EncodedKeyId,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
                    OutputPrefixTypeEnum::kTink,
                    JwtRsaSsaPssParameters::Algorithm::kPs256,
                    JwtRsaSsaPssAlgorithm::PS256,
                    /*modulus_size_in_bits=*/2048,
                    /*kid=*/"AgMEAA", /*id=*/0x02030400},
           TestCase{/*strategy=*/JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    OutputPrefixTypeEnum::kRaw,
                    JwtRsaSsaPssParameters::Algorithm::kPs384,
                    JwtRsaSsaPssAlgorithm::PS384,
                    /*modulus_size_in_bits=*/2048,
                    /*kid=*/absl::nullopt,
                    /*id=*/absl::nullopt},
           TestCase{/*strategy=*/JwtRsaSsaPssParameters::KidStrategy::kCustom,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    OutputPrefixTypeEnum::kRaw,
                    JwtRsaSsaPssParameters::Algorithm::kPs512,
                    JwtRsaSsaPssAlgorithm::PS512,
                    /*modulus_size_in_bits=*/2048,
                    /*kid=*/"custom_kid",
                    /*id=*/absl::nullopt}));

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParseParametersSucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
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

  absl::StatusOr<const JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParseParametersSucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  JwtRsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
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

  absl::StatusOr<const JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_version(1);  // invalid version number
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

using JwtRsaSsaPssParseInvalidPrefixTest = TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(JwtRsaSsaPssParseInvalidPrefixTestSuite,
                         JwtRsaSsaPssParseInvalidPrefixTest,
                         Values(OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(JwtRsaSsaPssParseInvalidPrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);

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
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat")));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParseParametersWithUnknownAlgorithmFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS_UNKNOWN);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtRsaSsaPssAlgorithm")));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializeParametersSucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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
      Eq(static_cast<OutputPrefixTypeEnum>(test_case.output_prefix_type)));
  JwtRsaSsaPssKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  EXPECT_THAT(key_format.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializeParametersSucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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
      Eq(static_cast<OutputPrefixTypeEnum>(test_case.output_prefix_type)));
  JwtRsaSsaPssKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  EXPECT_THAT(key_format.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       SerializeParametersWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kCustom)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
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
                         "JwtRsaSsaPssParameters::KidStrategy::kCustom")));
}

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

KeyValues GenerateKeyValues(int modulus_size_in_bits) {
  SslUniquePtr<RSA> rsa(RSA_new());
  ABSL_CHECK_NE(rsa.get(), nullptr);

  // Set public exponent to 65537.
  SslUniquePtr<BIGNUM> e(BN_new());
  ABSL_CHECK_NE(e.get(), nullptr);
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  ABSL_CHECK(RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e.get(),
                                 /*cb=*/nullptr));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;

  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  absl::StatusOr<std::string> n_str = BignumToString(n_bn, BN_num_bytes(n_bn));
  ABSL_CHECK_OK(n_str);
  absl::StatusOr<std::string> e_str = BignumToString(e_bn, BN_num_bytes(e_bn));
  ABSL_CHECK_OK(e_str);
  absl::StatusOr<std::string> d_str =
      BignumToString(d_bn, (modulus_size_in_bits + 7) / 8);
  ABSL_CHECK_OK(d_str);

  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);

  absl::StatusOr<std::string> p_str = BignumToString(p_bn, BN_num_bytes(p_bn));
  ABSL_CHECK_OK(p_str);
  absl::StatusOr<std::string> q_str = BignumToString(q_bn, BN_num_bytes(q_bn));
  ABSL_CHECK_OK(q_str);

  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  absl::StatusOr<std::string> dp_str =
      BignumToString(dp_bn, BN_num_bytes(p_bn));
  ABSL_CHECK_OK(dp_str);
  absl::StatusOr<std::string> dq_str =
      BignumToString(dq_bn, BN_num_bytes(q_bn));
  ABSL_CHECK_OK(dq_str);
  absl::StatusOr<std::string> q_inv_str =
      BignumToString(q_inv_bn, BN_num_bytes(p_bn));
  ABSL_CHECK_OK(q_inv_str);

  return KeyValues{*n_str,  *e_str,  *p_str, *q_str,
                   *dp_str, *dq_str, *d_str, *q_inv_str};
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParsePublicKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::JwtRsaSsaPssPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParsePublicKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::JwtRsaSsaPssPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder public_key_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> expected_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);
  google::crypto::tink::JwtRsaSsaPssPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParseTinkPublicKeyWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);
  google::crypto::tink::JwtRsaSsaPssPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
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
  // downstream while building JwtRsaSsaPssPublicKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPssParseInvalidPrefixTest,
       ParsePublicKeyWithInvalidPrefixFails) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
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
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat")));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParsePublicKeyWithInvalidAlgorithmFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  JwtRsaSsaPssKeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS_UNKNOWN);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(parsed_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtRsaSsaPssAlgorithm")));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializePublicKeySucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> key =
      builder.Build(GetPartialKeyAccess());
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

  google::crypto::tink::JwtRsaSsaPssPublicKey proto_key;
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
      Eq(test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializePublicKeySucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder public_key_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> key =
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

  google::crypto::tink::JwtRsaSsaPssPublicKey proto_key;
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
      Eq(test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> expected_private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetPrimeP(
              RestrictedData(key_values.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(key_values.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       PrivateKeyAndSerializationWithPaddingSucceeds) {
  KeyValues key_values = GenerateKeyValues(2048);
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(key_values.p, token))
          .SetPrimeQ(RestrictedData(key_values.q, token))
          .SetPrimeExponentP(RestrictedData(key_values.dp, token))
          .SetPrimeExponentQ(RestrictedData(key_values.dq, token))
          .SetPrivateExponent(RestrictedData(key_values.d, token))
          .SetCrtCoefficient(RestrictedData(key_values.q_inv, token))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
      {FieldWithNumber(2).IsSubMessage({
           FieldWithNumber(2).IsVarint(JwtRsaSsaPssAlgorithm::PS256),
           FieldWithNumber(3).IsString(key_values.n),
           FieldWithNumber(4).IsString(key_values.e),
       }),
       // We pad each number with some zeros to get non-canonical padding.
       FieldWithNumber(4).IsString(
           absl::StrCat("\x00\x00", key_values.p)),  // Not ordered
       FieldWithNumber(5).IsString(absl::StrCat("\x00\x00\x00", key_values.q)),
       FieldWithNumber(6).IsString(absl::StrCat("\x00\x00\x00", key_values.dp)),
       FieldWithNumber(7).IsString(absl::StrCat("\x00\x00", key_values.dq)),
       FieldWithNumber(3).IsString(
           absl::StrCat("\x00\x00\x00\x00", key_values.d)),
       FieldWithNumber(8).IsString(absl::StrCat("\x00", key_values.q_inv))},
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(serialization, InsecureSecretKeyAccess::Get());

  ASSERT_THAT(key.status(), IsOk());
  EXPECT_TRUE(**key == *private_key);
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(test_case.proto_algorithm);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_proto.mutable_custom_kid()->set_value(test_case.kid.value());
  }

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPssParameters> expected_parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder public_key_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> expected_public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> expected_private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetPrimeP(
              RestrictedData(key_values.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(key_values.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersionFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(1);  // invalid version number
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 public keys are accepted")));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithoutPublicKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPssParseInvalidPrefixTest,
       ParsePrivateKeyWithInvalidPrefixFails) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    invalid_output_prefix_type,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPssKeyFormat")));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       ParsePrivateKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
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
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializePrivateKeySucceedsWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(key_values.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(key_values.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(key_values.q_inv, InsecureSecretKeyAccess::Get()))
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPssPrivateKey proto_key;
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
      Eq(test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom));
}

TEST_P(JwtRsaSsaPssProtoSerializationTest,
       SerializePrivateKeySucceedsWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  JwtRsaSsaPssPublicKey::Builder public_key_builder =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n));
  if (test_case.id.has_value()) {
    public_key_builder.SetIdRequirement(*test_case.id);
  }
  if (test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom) {
    public_key_builder.SetCustomKid(test_case.kid.value());
  }
  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      public_key_builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(key_values.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(key_values.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(key_values.q_inv, InsecureSecretKeyAccess::Get()))
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::JwtRsaSsaPssPrivateKey proto_key;
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
      Eq(test_case.strategy == JwtRsaSsaPssParameters::KidStrategy::kCustom));
}

TEST_F(JwtRsaSsaPssProtoSerializationTest,
       SerializePrivateKeyNoSecretKeyAccessFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterJwtRsaSsaPssProtoSerializationWithMutableRegistry(registry),
      IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(key_values.n))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedData(key_values.p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedData(key_values.q, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
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
