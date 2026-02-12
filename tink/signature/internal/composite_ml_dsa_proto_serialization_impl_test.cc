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

#include "tink/signature/internal/composite_ml_dsa_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/parameters.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/util/test_matchers.h"
#include "proto/composite_ml_dsa.pb.h"
#include "proto/ml_dsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::CompositeMlDsaClassicalAlgorithm;
using ::google::crypto::tink::CompositeMlDsaKeyFormat;
using ::google::crypto::tink::CompositeMlDsaParams;
using ::google::crypto::tink::MlDsaInstance;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";

struct TestCase {
  CompositeMlDsaParameters::MlDsaInstance ml_dsa_instance;
  CompositeMlDsaParameters::ClassicalAlgorithm classical_algorithm;
  CompositeMlDsaParameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using CompositeMlDsaProtoSerializationTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    CompositeMlDsaProtoSerializationTestSuite,
    CompositeMlDsaProtoSerializationTest,
    Values(TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""},
           TestCase{CompositeMlDsaParameters::MlDsaInstance::kMlDsa87,
                    CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss,
                    CompositeMlDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)}));

MlDsaInstance ToProtoInstance(
    CompositeMlDsaParameters::MlDsaInstance instance) {
  switch (instance) {
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa65:
      return MlDsaInstance::ML_DSA_65;
    case CompositeMlDsaParameters::MlDsaInstance::kMlDsa87:
      return MlDsaInstance::ML_DSA_87;
    default:
      return MlDsaInstance::ML_DSA_UNKNOWN_INSTANCE;
  }
}

CompositeMlDsaClassicalAlgorithm ToProtoAlgorithm(
    CompositeMlDsaParameters::ClassicalAlgorithm algorithm) {
  switch (algorithm) {
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP256:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ECDSA_P256;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP384:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ECDSA_P384;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kEcdsaP521:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ECDSA_P521;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pss:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_RSA3072_PSS;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pss:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_RSA4096_PSS;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa3072Pkcs1:
      return CompositeMlDsaClassicalAlgorithm::
          CLASSICAL_ALGORITHM_RSA3072_PKCS1;
    case CompositeMlDsaParameters::ClassicalAlgorithm::kRsa4096Pkcs1:
      return CompositeMlDsaClassicalAlgorithm::
          CLASSICAL_ALGORITHM_RSA4096_PKCS1;
    default:
      return CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_UNKNOWN;
  }
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(builder),
      IsOk());
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParseParametersWorksWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  CompositeMlDsaKeyFormat key_format_proto;
  CompositeMlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(),
            test_case.id_requirement.has_value());

  const CompositeMlDsaParameters* composite_parameters =
      dynamic_cast<const CompositeMlDsaParameters*>(parameters->get());
  ASSERT_THAT(composite_parameters, NotNull());
  EXPECT_EQ(composite_parameters->GetMlDsaInstance(),
            test_case.ml_dsa_instance);
  EXPECT_EQ(composite_parameters->GetClassicalAlgorithm(),
            test_case.classical_algorithm);
  EXPECT_EQ(composite_parameters->GetVariant(), test_case.variant);
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParseParametersWorksWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  CompositeMlDsaKeyFormat key_format_proto;
  CompositeMlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(),
            test_case.id_requirement.has_value());

  const CompositeMlDsaParameters* composite_parameters =
      dynamic_cast<const CompositeMlDsaParameters*>(parameters->get());
  ASSERT_THAT(composite_parameters, NotNull());
  EXPECT_EQ(composite_parameters->GetMlDsaInstance(),
            test_case.ml_dsa_instance);
  EXPECT_EQ(composite_parameters->GetClassicalAlgorithm(),
            test_case.classical_algorithm);
  EXPECT_EQ(composite_parameters->GetVariant(), test_case.variant);
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(registry.ParseParameters(*serialization).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse CompositeMlDsaKeyFormat "
                                 "proto")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  CompositeMlDsaKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  CompositeMlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  CompositeMlDsaKeyFormat key_format_proto;
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);

  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine CompositeMlDsaParameters")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParseParametersWithUnknownOutputPrefixFails) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  CompositeMlDsaKeyFormat key_format_proto;
  CompositeMlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine CompositeMlDsaParameters::"
                         "Variant")));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParseParametersWithInvalidMlDsaInstanceFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());
  {
    // Unknown ML-DSA instance.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_UNKNOWN_INSTANCE);
    params.set_classical_algorithm(
        CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "MlDsaInstance")));
  }
  {
    // Out of range instance - too large.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(static_cast<MlDsaInstance>(3));
    params.set_classical_algorithm(
        CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "MlDsaInstance")));
  }
  {
    // Out of range instance - too small.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(static_cast<MlDsaInstance>(-1));
    params.set_classical_algorithm(
        CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "MlDsaInstance")));
  }
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParseParametersWithInvalidClassicalAlgorithmFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());
  {
    // Unknown ML-DSA instance.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
    params.set_classical_algorithm(
        CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_UNKNOWN);

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "ClassicalAlgorithm")));
  }
  {
    // Out of range instance - too large.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
    params.set_classical_algorithm(
        static_cast<CompositeMlDsaClassicalAlgorithm>(9));

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "ClassicalAlgorithm")));
  }
  {
    // Out of range instance - too small.
    CompositeMlDsaKeyFormat key_format_proto;
    CompositeMlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
    params.set_classical_algorithm(
        static_cast<CompositeMlDsaClassicalAlgorithm>(-1));

    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        registry.ParseParameters(*serialization);

    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine CompositeMlDsaParameters::"
                           "ClassicalAlgorithm")));
  }
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializeParametersWorksWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
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

  CompositeMlDsaKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(key_format.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializeParametersWorksWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithRegistryBuilder(builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
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

  CompositeMlDsaKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(key_format.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       RoundTripCompositeMlDsaParametersWorks) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(test_case.ml_dsa_instance,
                                       test_case.classical_algorithm,
                                       test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(*proto_serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
