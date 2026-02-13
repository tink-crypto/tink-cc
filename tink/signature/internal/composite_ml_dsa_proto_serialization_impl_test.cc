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
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/composite_ml_dsa_parameters.h"
#include "tink/signature/composite_ml_dsa_private_key.h"
#include "tink/signature/composite_ml_dsa_public_key.h"
#include "tink/signature/internal/ecdsa_proto_serialization_impl.h"
#include "tink/signature/internal/ed25519_proto_serialization_impl.h"
#include "tink/signature/internal/ml_dsa_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pkcs1_proto_serialization_impl.h"
#include "tink/signature/internal/rsa_ssa_pss_proto_serialization_impl.h"
#include "tink/signature/internal/testing/composite_ml_dsa_test_util.h"
#include "tink/signature/signature_private_key.h"
#include "tink/signature/signature_public_key.h"
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
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlDsaInstance;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPrivateKey";
constexpr absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.CompositeMlDsaPublicKey";

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

KeyData::KeyMaterialType ToProtoKeyMaterialType(
    KeyMaterialTypeEnum key_material_type) {
  switch (key_material_type) {
    case KeyMaterialTypeEnum::kSymmetric:
      return KeyData::SYMMETRIC;
    case KeyMaterialTypeEnum::kAsymmetricPrivate:
      return KeyData::ASYMMETRIC_PRIVATE;
    case KeyMaterialTypeEnum::kAsymmetricPublic:
      return KeyData::ASYMMETRIC_PUBLIC;
    case KeyMaterialTypeEnum::kRemote:
      return KeyData::REMOTE;
    default:
      return KeyData::UNKNOWN_KEYMATERIAL;
  }
}

absl::StatusOr<KeyData> SerializeKey(const Key& key) {
  SerializationRegistry::Builder builder;
  absl::Status status =
      RegisterMlDsaProtoSerializationWithRegistryBuilder(builder);
  if (!status.ok()) return status;
  status = RegisterRsaSsaPkcs1ProtoSerializationWithRegistryBuilder(builder);
  if (!status.ok()) return status;
  status = RegisterRsaSsaPssProtoSerializationWithRegistryBuilder(builder);
  if (!status.ok()) return status;
  status = RegisterEcdsaProtoSerializationWithRegistryBuilder(builder);
  if (!status.ok()) return status;
  status = RegisterEd25519ProtoSerializationWithRegistryBuilder(builder);
  if (!status.ok()) return status;
  absl::StatusOr<SerializationRegistry> registry = std::move(builder).Build();
  if (!registry.ok()) {
    return registry.status();
  }
  absl::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry->SerializeKey<ProtoKeySerialization>(
          key, InsecureSecretKeyAccess::Get());
  if (!key_serialization.ok()) {
    return key_serialization.status();
  }
  absl::StatusOr<std::unique_ptr<ProtoKeySerialization>>
      proto_key_serialization =
          DynamicCast<ProtoKeySerialization>(std::move(*key_serialization));
  if (!proto_key_serialization.ok()) {
    return proto_key_serialization.status();
  }
  KeyData key_data;
  key_data.set_type_url((*proto_key_serialization)->TypeUrl());
  key_data.set_key_material_type(ToProtoKeyMaterialType(
      (*proto_key_serialization)->GetKeyMaterialTypeEnum()));
  key_data.set_value((*proto_key_serialization)
                         ->SerializedKeyProto()
                         .GetSecret(InsecureSecretKeyAccess::Get()));
  return key_data;
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

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePublicKeyWorksWithMutableRegistry) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_public_key =
      SerializeKey(private_key.GetMlDsaPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_ml_dsa_public_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_public_key =
      SerializeKey(private_key.GetClassicalPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_classical_public_key, IsOk());

  google::crypto::tink::CompositeMlDsaPublicKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_public_key() = *serialized_ml_dsa_public_key;
  *key_proto.mutable_classical_public_key() = *serialized_classical_public_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      CloneKeyOrDie<SignaturePublicKey>(
          private_key.GetClassicalPrivateKey().GetPublicKey());

  absl::StatusOr<CompositeMlDsaPublicKey> expected_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey().GetPublicKey(),
          std::move(classical_public_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePublicKeyWorksWithRegistryBuilder) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_public_key =
      SerializeKey(private_key.GetMlDsaPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_ml_dsa_public_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_public_key =
      SerializeKey(private_key.GetClassicalPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_classical_public_key, IsOk());

  google::crypto::tink::CompositeMlDsaPublicKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_public_key() = *serialized_ml_dsa_public_key;
  *key_proto.mutable_classical_public_key() = *serialized_classical_public_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      CloneKeyOrDie<SignaturePublicKey>(
          private_key.GetClassicalPrivateKey().GetPublicKey());

  absl::StatusOr<CompositeMlDsaPublicKey> expected_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey().GetPublicKey(),
          std::move(classical_public_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidKeyMaterialTypeFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(private_key.GetPublicKey(),
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  const ProtoKeySerialization* public_key_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(public_key_serialization, NotNull());

  absl::StatusOr<ProtoKeySerialization> proto_serialization =
      ProtoKeySerialization::Create(
          kPublicTypeUrl, public_key_serialization->SerializedKeyProto(),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*proto_serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Wrong key material type when parsing CompositeMlDsaPublicKey")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse CompositeMlDsaPublicKey proto")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_public_key =
      SerializeKey(private_key.GetMlDsaPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_ml_dsa_public_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_public_key =
      SerializeKey(private_key.GetClassicalPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_classical_public_key, IsOk());

  google::crypto::tink::CompositeMlDsaPublicKey key_proto;
  key_proto.set_version(1);
  *key_proto.mutable_ml_dsa_public_key() = *serialized_ml_dsa_public_key;
  *key_proto.mutable_classical_public_key() = *serialized_classical_public_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializePublicKeyWorksWithMutableRegistry) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      CloneKeyOrDie<SignaturePublicKey>(
          private_key.GetClassicalPrivateKey().GetPublicKey());

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey().GetPublicKey(),
          std::move(classical_public_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::CompositeMlDsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(proto_key.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializePublicKeyWorksWithRegistryBuilder) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      CloneKeyOrDie<SignaturePublicKey>(
          private_key.GetClassicalPrivateKey().GetPublicKey());

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey().GetPublicKey(),
          std::move(classical_public_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::CompositeMlDsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(proto_key.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       RoundTripCompositeMlDsaPublicKeyWorks) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  std::unique_ptr<SignaturePublicKey> classical_public_key_clone =
      CloneKeyOrDie<SignaturePublicKey>(
          private_key.GetClassicalPrivateKey().GetPublicKey());

  absl::StatusOr<CompositeMlDsaPublicKey> public_key =
      CompositeMlDsaPublicKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey().GetPublicKey(),
          std::move(classical_public_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*proto_serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  ASSERT_THAT(**parsed_key, Eq(*public_key));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWorksWithMutableRegistry) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      CloneKeyOrDie<SignaturePrivateKey>(private_key.GetClassicalPrivateKey());

  absl::StatusOr<CompositeMlDsaPrivateKey> expected_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey(),
          std::move(classical_private_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWorksWithRegistryBuilder) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  std::unique_ptr<SignaturePrivateKey> classical_private_key_clone =
      CloneKeyOrDie<SignaturePrivateKey>(private_key.GetClassicalPrivateKey());

  absl::StatusOr<CompositeMlDsaPrivateKey> expected_key =
      CompositeMlDsaPrivateKey::Create(
          *parameters, private_key.GetMlDsaPrivateKey(),
          std::move(classical_private_key_clone), test_case.id_requirement,
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidKeyMaterialTypeFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  const ProtoKeySerialization* private_key_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(private_key_serialization, NotNull());

  absl::StatusOr<ProtoKeySerialization> proto_serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, private_key_serialization->SerializedKeyProto(),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*proto_serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Wrong key material type when parsing "
                                 "CompositeMlDsaPrivateKey")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse CompositeMlDsaPrivateKey proto")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(1);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyNoSecretKeyAccessFails) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(ToProtoInstance(test_case.ml_dsa_instance));
  params.set_classical_algorithm(
      ToProtoAlgorithm(test_case.classical_algorithm));

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    test_case.output_prefix_type,
                                    test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidMlDsaKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
  params.set_classical_algorithm(
      CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  // Invalidate the ML-DSA key.
  serialized_ml_dsa_private_key->clear_value();
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

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

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithInvalidClassicalKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
  params.set_classical_algorithm(
      CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  // Invalidate the classical key.
  serialized_classical_private_key->clear_value();
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

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

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithWithPublicMlDsaKeyAsPrivateMlDsaKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
  params.set_classical_algorithm(
      CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

  absl::StatusOr<KeyData> serialized_ml_dsa_public_key =
      SerializeKey(private_key.GetMlDsaPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_ml_dsa_public_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_private_key =
      SerializeKey(private_key.GetClassicalPrivateKey());
  ASSERT_THAT(serialized_classical_private_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  // Use an ML-DSA public key as the ML-DSA private key.
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_public_key;
  *key_proto.mutable_classical_private_key() =
      *serialized_classical_private_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Parsed ML-DSA key is not an MlDsaPrivateKey")));
}

TEST_F(CompositeMlDsaProtoSerializationTest,
       ParsePrivateKeyWithWithPublicClassicalKeyAsPrivateClassicalKeyFails) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterCompositeMlDsaProtoSerializationWithMutableRegistry(registry),
      IsOk());

  absl::StatusOr<CompositeMlDsaParameters> parameters =
      CompositeMlDsaParameters::Create(
          CompositeMlDsaParameters::MlDsaInstance::kMlDsa65,
          CompositeMlDsaParameters::ClassicalAlgorithm::kEd25519,
          CompositeMlDsaParameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false,
          /*id_requirement=*/absl::nullopt);

  CompositeMlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);
  params.set_classical_algorithm(
      CompositeMlDsaClassicalAlgorithm::CLASSICAL_ALGORITHM_ED25519);

  absl::StatusOr<KeyData> serialized_ml_dsa_private_key =
      SerializeKey(private_key.GetMlDsaPrivateKey());
  ASSERT_THAT(serialized_ml_dsa_private_key, IsOk());
  absl::StatusOr<KeyData> serialized_classical_public_key =
      SerializeKey(private_key.GetClassicalPrivateKey().GetPublicKey());
  ASSERT_THAT(serialized_classical_public_key, IsOk());

  google::crypto::tink::CompositeMlDsaPrivateKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_ml_dsa_private_key() = *serialized_ml_dsa_private_key;
  // Use a classical public key as the classical private key.
  *key_proto.mutable_classical_private_key() = *serialized_classical_public_key;
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Parsed classical key is not a SignaturePrivateKey")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializePrivateKeyWorksWithMutableRegistry) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          private_key, InsecureSecretKeyAccess::Get());
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
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::CompositeMlDsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.has_ml_dsa_private_key(), IsTrue());
  EXPECT_THAT(proto_key.has_classical_private_key(), IsTrue());
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(proto_key.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializePrivateKeyWorksWithRegistryBuilder) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          private_key, InsecureSecretKeyAccess::Get());
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
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::CompositeMlDsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.has_ml_dsa_private_key(), IsTrue());
  EXPECT_THAT(proto_key.has_classical_private_key(), IsTrue());
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_dsa_instance(),
              Eq(ToProtoInstance(test_case.ml_dsa_instance)));
  EXPECT_THAT(proto_key.params().classical_algorithm(),
              Eq(ToProtoAlgorithm(test_case.classical_algorithm)));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       SerializePrivateKeyNoSecretKeyAccessFails) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(private_key,
                                                   /*token=*/absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

TEST_P(CompositeMlDsaProtoSerializationTest,
       RoundTripCompositeMlDsaPrivateKeyWorks) {
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

  CompositeMlDsaPrivateKey private_key =
      GenerateCompositeMlDsaPrivateKeyForTestOrDie(
          *parameters, /*force_random=*/false, test_case.id_requirement);

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      registry.ParseKey(*proto_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(private_key));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
