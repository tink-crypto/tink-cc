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
#include "tink/jwt/jwt_rsa_ssa_pkcs1_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/tink_proto_structs.h"
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
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPkcs1Parameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtRsaSsaPkcs1Parameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeEnum output_prefix_type;
  JwtRsaSsaPkcs1Parameters::Algorithm algorithm;
  JwtRsaSsaPkcs1Algorithm proto_algorithm;
  int modulus_size_in_bits;
  absl::optional<std::string> kid;
  absl::optional<int> id;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537
constexpr int kModulusSizeInBits = 2048;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey";

class JwtRsaSsaPkcs1ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  JwtRsaSsaPkcs1ProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPkcs1ProtoSerializationTestSuite,
    JwtRsaSsaPkcs1ProtoSerializationTest,
    Values(TestCase{/*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::
                        kBase64EncodedKeyId,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
                    OutputPrefixTypeEnum::kTink,
                    JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                    JwtRsaSsaPkcs1Algorithm::RS256,
                    /*modulus_size_in_bits=*/2048,
                    /*kid=*/"AgMEAA", /*id=*/0x02030400},
           TestCase{
               /*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
               /*expected_parameters_strategy=*/
               JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
               OutputPrefixTypeEnum::kRaw,
               JwtRsaSsaPkcs1Parameters::Algorithm::kRs384,
               JwtRsaSsaPkcs1Algorithm::RS384,
               /*modulus_size_in_bits=*/2048,
               /*kid=*/absl::nullopt,
               /*id=*/absl::nullopt},
           TestCase{/*strategy=*/JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom,
                    /*expected_parameters_strategy=*/
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                    OutputPrefixTypeEnum::kRaw,
                    JwtRsaSsaPkcs1Parameters::Algorithm::kRs512,
                    JwtRsaSsaPkcs1Algorithm::RS512,
                    /*modulus_size_in_bits=*/2048,
                    /*kid=*/"custom_kid",
                    /*id=*/absl::nullopt}));

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(test_case.proto_algorithm);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<const JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(1);  // invalid version number
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

using JwtRsaSsaPkcs1ParseInvalidPrefixTest =
    TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(JwtRsaSsaPkcs1ParseInvalidPrefixTestSuite,
                         JwtRsaSsaPkcs1ParseInvalidPrefixTest,
                         Values(OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, invalid_output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithUnknownAlgorithmFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine JwtRsaSsaPkcs1Algorithm")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, SerializeParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.expected_parameters_strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));
  JwtRsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());

  EXPECT_THAT(key_format.algorithm(), Eq(test_case.proto_algorithm));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       SerializeParametersWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  EXPECT_THAT(
      serialization.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unable to serialize "
                         "JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom")));
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
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  CHECK_NE(rsa.get(), nullptr);

  // Set public exponent to 65537.
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  CHECK_NE(e.get(), nullptr);
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  CHECK(RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e.get(),
                            /*cb=*/nullptr));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;

  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  absl::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  CHECK_OK(n_str);
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  CHECK_OK(e_str);
  absl::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  CHECK_OK(d_str);

  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);

  absl::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  CHECK_OK(p_str);
  absl::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  CHECK_OK(q_str);

  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  absl::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  CHECK_OK(dp_str);
  absl::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  CHECK_OK(dq_str);
  absl::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  CHECK_OK(q_inv_str);

  return KeyValues{*n_str,  *e_str,  *p_str, *q_str,
                   *dp_str, *dq_str, *d_str, *q_inv_str};
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, ParsePublicKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);
  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParseTinkPublicKeyWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);
  google::crypto::tink::JwtRsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtRsaSsaPkcs1PublicKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest,
       ParsePublicKeyWithInvalidPrefixFails) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, invalid_output_prefix_type,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidAlgorithmFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  JwtRsaSsaPkcs1KeyFormat key_proto;
  key_proto.set_version(0);
  key_proto.set_modulus_size_in_bits(2048);
  key_proto.set_public_exponent(kF4Str);
  key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS_UNKNOWN);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      parsed_key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine JwtRsaSsaPkcs1Algorithm")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, SerializePublicKeySucceeds) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
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

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, ParsePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> expected_parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**parsed_key, Eq(*expected_private_key));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersionFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 public keys are accepted")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithoutPublicKeyFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(JwtRsaSsaPkcs1ParseInvalidPrefixTest,
       ParsePrivateKeyWithInvalidPrefixFails) {
  OutputPrefixTypeEnum invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, invalid_output_prefix_type,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid OutputPrefixType for JwtRsaSsaPkcs1KeyFormat")));
}

TEST_F(JwtRsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(JwtRsaSsaPkcs1ProtoSerializationTest, SerializePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(test_case.strategy)
          .SetAlgorithm(test_case.algorithm)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
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
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
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
  ASSERT_THAT(RegisterJwtRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

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
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
