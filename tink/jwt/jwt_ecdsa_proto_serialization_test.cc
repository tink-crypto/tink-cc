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
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/parameters.h"
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
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

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

}  // namespace
}  // namespace tink
}  // namespace crypto
