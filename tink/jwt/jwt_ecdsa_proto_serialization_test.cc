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

#include "tink/jwt/jwt_ecdsa_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
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
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtEcdsaKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
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
  OutputPrefixType output_prefix_type;
  JwtEcdsaParameters::Algorithm algorithm;
  JwtEcdsaAlgorithm proto_algorithm;
  subtle::EllipticCurveType curve;
  absl::optional<std::string> expected_kid;
  absl::optional<int> id;
  std::string output_prefix;
};

class JwtEcdsaProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtEcdsaProtoSerializationTest, RegisterTwiceSucceeds) {
  EXPECT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());
  EXPECT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtEcdsaProtoSerializationTestSuite, JwtEcdsaProtoSerializationTest,
    Values(
        TestCase{JwtEcdsaParameters::KidStrategy::kBase64EncodedKeyId,
                 OutputPrefixType::TINK, JwtEcdsaParameters::Algorithm::kEs256,
                 JwtEcdsaAlgorithm::ES256, subtle::EllipticCurveType::NIST_P256,
                 /*expected_kid=*/"AgMEAA", /*id=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{JwtEcdsaParameters::KidStrategy::kIgnored,
                 OutputPrefixType::RAW, JwtEcdsaParameters::Algorithm::kEs384,
                 JwtEcdsaAlgorithm::ES384, subtle::EllipticCurveType::NIST_P384,
                 /*expected_kid=*/absl::nullopt, /*id=*/absl::nullopt,
                 /*output_prefix=*/""},
        TestCase{JwtEcdsaParameters::KidStrategy::kIgnored,
                 OutputPrefixType::RAW, JwtEcdsaParameters::Algorithm::kEs512,
                 JwtEcdsaAlgorithm::ES512, subtle::EllipticCurveType::NIST_P521,
                 /*expected_kid=*/absl::nullopt, /*id=*/absl::nullopt,
                 /*output_prefix=*/""}));

TEST_P(JwtEcdsaProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(test_case.proto_algorithm);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT((*parsed)->HasIdRequirement(), test_case.id.has_value());

  util::StatusOr<JwtEcdsaParameters> expected =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(JwtEcdsaProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse JwtEcdsaKeyFormat proto")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_algorithm(JwtEcdsaAlgorithm::ES256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseParametersWithUnknownAlgorithm) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtEcdsaAlgorithm")));
}

using JwtEcdsaParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(JwtEcdsaParsePrefixTestSuite, JwtEcdsaParsePrefixTest,
                         Values(OutputPrefixType::CRUNCHY,
                                OutputPrefixType::LEGACY,
                                OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(JwtEcdsaParsePrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  JwtEcdsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtEcdsaAlgorithm::ES256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, invalid_output_prefix_type,
          format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtEcdsaKeyFormat")));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  JwtEcdsaKeyFormat format;
  ASSERT_THAT(
      format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_F(JwtEcdsaProtoSerializationTest, SerializeParametersWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to serialize "
                                 "JwtEcdsaParameters::KidStrategy::kCustom")));
}

TEST_P(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithoutCustomKid) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(test_case.proto_algorithm);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(test_case.id));

  util::StatusOr<JwtEcdsaParameters> expected_parameters =
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
  util::StatusOr<JwtEcdsaPublicKey> expected_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithCustomKid) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::RAW,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT((*parsed_key)->GetParameters().HasIdRequirement(), IsFalse());
  EXPECT_THAT((*parsed_key)->GetIdRequirement(), Eq(absl::nullopt));

  util::StatusOr<JwtEcdsaParameters> expected_parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(expected_parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> expected_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetPublicPoint(public_point)
          .SetCustomKid(key_proto.custom_kid().value())
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParseTinkPublicKeyWithCustomKidFails) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  key_proto.mutable_custom_kid()->set_value("custom_kid");
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          OutputPrefixType::TINK, /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  // Omitting expectation on specific error message since the error occurs
  // downstream while building JwtEcdsaPublicKey object.
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          OutputPrefixType::RAW, /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse JwtEcdsaPublicKey proto")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::RAW,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Parsing JwtEcdsaPublicKey failed: only version 0 is accepted")));
}

TEST_P(JwtEcdsaParsePrefixTest, ParsePublicKeyWithInvalidPrefix) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              invalid_output_prefix_type,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid OutputPrefixType for JwtEcdsaKeyFormat")));
}

TEST_F(JwtEcdsaProtoSerializationTest, ParsePublicKeyWithUnknownAlgorithm) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_algorithm(JwtEcdsaAlgorithm::ES_UNKNOWN);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::RAW,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtEcdsaAlgorithm")));
}

TEST_P(JwtEcdsaProtoSerializationTest, SerializePublicKeyWithoutCustomKid) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(test_case.strategy, test_case.algorithm);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(test_case.curve);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  JwtEcdsaPublicKey::Builder builder = JwtEcdsaPublicKey::Builder()
                                           .SetParameters(*parameters)
                                           .SetPublicPoint(public_point);
  if (test_case.id.has_value()) {
    builder.SetIdRequirement(*test_case.id);
  }
  util::StatusOr<JwtEcdsaPublicKey> key = builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
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
  EXPECT_THAT(proto_key.has_custom_kid(), IsFalse());
}

TEST_F(JwtEcdsaProtoSerializationTest, SerializePublicKeyWithCustomKid) {
  ASSERT_THAT(RegisterJwtEcdsaProtoSerialization(), IsOk());

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kCustom,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> key = JwtEcdsaPublicKey::Builder()
                                              .SetParameters(*parameters)
                                              .SetPublicPoint(public_point)
                                              .SetCustomKid("custom_kid")
                                              .Build(GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(OutputPrefixType::RAW));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

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
  EXPECT_THAT(proto_key.algorithm(), Eq(JwtEcdsaAlgorithm::ES256));
  ASSERT_THAT(proto_key.has_custom_kid(), IsTrue());
  EXPECT_THAT(proto_key.custom_kid().value(), Eq(*key->GetKid()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
