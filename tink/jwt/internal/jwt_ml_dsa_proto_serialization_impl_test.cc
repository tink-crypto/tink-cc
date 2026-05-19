// Copyright 2026 Google LLC
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

#include "tink/jwt/internal/jwt_ml_dsa_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_ml_dsa_parameters.h"
#include "tink/parameters.h"
#include "proto/common.pb.h"
#include "proto/jwt_ml_dsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::JwtMlDsaAlgorithm;
using ::google::crypto::tink::JwtMlDsaKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.JwtMlDsaPrivateKey";

struct TestCase {
  JwtMlDsaParameters::KidStrategy strategy;
  // Helper member for parsing/serializing parameters with custom kid strategy.
  JwtMlDsaParameters::KidStrategy expected_parameters_strategy;
  OutputPrefixTypeTP output_prefix_type;
  JwtMlDsaParameters::Algorithm algorithm;
  JwtMlDsaAlgorithm proto_algorithm;
  absl::optional<std::string> kid;
  absl::optional<int> id;
  std::string output_prefix;
};

using JwtMlDsaProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(JwtMlDsaProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  EXPECT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());
  EXPECT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(JwtMlDsaProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  EXPECT_THAT(RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  EXPECT_THAT(RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    JwtMlDsaProtoSerializationTests, JwtMlDsaProtoSerializationTest,
    Values(
        TestCase{
            /*strategy=*/JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
            /*expected_parameters_strategy=*/
            JwtMlDsaParameters::KidStrategy::kBase64EncodedKeyId,
            OutputPrefixTypeTP::kTink, JwtMlDsaParameters::Algorithm::kMlDsa44,
            JwtMlDsaAlgorithm::ML_DSA44, /*kid=*/"AgMEAA", /*id=*/0x02030400,
            /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{/*strategy=*/JwtMlDsaParameters::KidStrategy::kIgnored,
                 /*expected_parameters_strategy=*/
                 JwtMlDsaParameters::KidStrategy::kIgnored,
                 OutputPrefixTypeTP::kRaw,
                 JwtMlDsaParameters::Algorithm::kMlDsa65,
                 JwtMlDsaAlgorithm::ML_DSA65, /*kid=*/absl::nullopt,
                 /*id=*/absl::nullopt, /*output_prefix=*/""},
        TestCase{/*strategy=*/JwtMlDsaParameters::KidStrategy::kCustom,
                 /*expected_parameters_strategy=*/
                 JwtMlDsaParameters::KidStrategy::kIgnored,
                 OutputPrefixTypeTP::kRaw,
                 JwtMlDsaParameters::Algorithm::kMlDsa87,
                 JwtMlDsaAlgorithm::ML_DSA87, /*kid=*/"custom_kid",
                 /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(JwtMlDsaProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtMlDsaKeyFormat format;
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

  absl::StatusOr<JwtMlDsaParameters> expected = JwtMlDsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_P(JwtMlDsaProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  JwtMlDsaKeyFormat format;
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

  absl::StatusOr<JwtMlDsaParameters> expected = JwtMlDsaParameters::Create(
      test_case.expected_parameters_strategy, test_case.algorithm);
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(JwtMlDsaProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeTP::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(JwtMlDsaProtoSerializationTest, ParseParametersWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtMlDsaKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_algorithm(JwtMlDsaAlgorithm::ML_DSA44);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           OutputPrefixTypeTP::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_F(JwtMlDsaProtoSerializationTest, ParseParametersWithUnknownAlgorithm) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtMlDsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtMlDsaAlgorithm::ML_DSA_UNKNOWN);

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kPrivateTypeUrl,
                                           OutputPrefixTypeTP::kRaw,
                                           format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine JwtMlDsaAlgorithm")));
}

using JwtMlDsaParsePrefixTest = TestWithParam<OutputPrefixTypeTP>;

INSTANTIATE_TEST_SUITE_P(JwtMlDsaParsePrefixTestSuite, JwtMlDsaParsePrefixTest,
                         Values(OutputPrefixTypeTP::kCrunchy,
                                OutputPrefixTypeTP::kLegacy,
                                OutputPrefixTypeTP::kUnknownPrefix));

TEST_P(JwtMlDsaParsePrefixTest, ParseParametersWithInvalidPrefix) {
  OutputPrefixTypeTP invalid_output_prefix_type = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  JwtMlDsaKeyFormat format;
  format.set_version(0);
  format.set_algorithm(JwtMlDsaAlgorithm::ML_DSA44);

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
               HasSubstr("Invalid OutputPrefixType for JwtMlDsaKeyFormat")));
}

TEST_P(JwtMlDsaProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
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
  JwtMlDsaKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_P(JwtMlDsaProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<JwtMlDsaParameters> parameters = JwtMlDsaParameters::Create(
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
  JwtMlDsaKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.algorithm(), Eq(test_case.proto_algorithm));
}

TEST_F(JwtMlDsaProtoSerializationTest, SerializeParametersWithCustomKidFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterJwtMlDsaProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<JwtMlDsaParameters> parameters =
      JwtMlDsaParameters::Create(JwtMlDsaParameters::KidStrategy::kCustom,
                                 JwtMlDsaParameters::Algorithm::kMlDsa44);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to serialize "
                                 "JwtMlDsaParameters::KidStrategy::kCustom")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
