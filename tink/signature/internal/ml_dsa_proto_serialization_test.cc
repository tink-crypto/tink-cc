// Copyright 2024 Google LLC
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

#include "tink/signature/internal/ml_dsa_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/signature/internal/key_creators.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/ml_dsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlDsaInstance;
using ::google::crypto::tink::MlDsaKeyFormat;
using ::google::crypto::tink::MlDsaParams;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlDsaPublicKey";

struct TestCase {
  MlDsaParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

class MlDsaProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  MlDsaProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    MlDsaProtoSerializationTestSuite, MlDsaProtoSerializationTest,
    Values(TestCase{MlDsaParameters::Variant::kTink, OutputPrefixType::TINK,
                    0x02030400, std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{MlDsaParameters::Variant::kTink, OutputPrefixType::TINK,
                    0x03050709, std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{MlDsaParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                    absl::nullopt, ""}));

MlDsaPrivateKey GenerateMlDsa65PrivateKey(MlDsaParameters::Variant variant,
                                          absl::optional<int> id_requirement) {
  absl::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  CHECK_OK(parameters);

  absl::StatusOr<std::unique_ptr<MlDsaPrivateKey>> private_key =
      internal::CreateMlDsaKey(*parameters, id_requirement);
  CHECK_OK(private_key);

  return **private_key;
}

TEST_F(MlDsaProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());
}

TEST_P(MlDsaProtoSerializationTest, ParseMlDsa65ParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  MlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(),
            test_case.id_requirement.has_value());

  const MlDsaParameters* ml_dsa_parameters =
      dynamic_cast<const MlDsaParameters*>(parameters->get());
  ASSERT_THAT(ml_dsa_parameters, NotNull());
  EXPECT_THAT(ml_dsa_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(ml_dsa_parameters->GetInstance(),
              Eq(MlDsaParameters::Instance::kMlDsa65));
}

TEST_F(MlDsaProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlDsaKeyFormat proto")));
}

TEST_F(MlDsaProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  MlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(MlDsaProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine MlDsaParameters::Instance")));
}

TEST_F(MlDsaProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  MlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine MlDsaParameters::Variant")));
}

TEST_F(MlDsaProtoSerializationTest, ParseParametersWithInvalidInstanceFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  {
    // Unknown instance.
    MlDsaKeyFormat key_format_proto;
    MlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_UNKNOWN_INSTANCE);

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixType::RAW,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine MlDsaParameters::Instance")));
  }
  {
    // Out of range instance - too large.
    MlDsaKeyFormat key_format_proto;
    MlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(static_cast<MlDsaInstance>(2));

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixType::RAW,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("Failed to parse MlDsaKeyFormat proto")));
  }
  {
    // Out of range instance - too small.
    MlDsaKeyFormat key_format_proto;
    MlDsaParams& params = *key_format_proto.mutable_params();
    params.set_ml_dsa_instance(static_cast<MlDsaInstance>(-1));

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixType::RAW,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("Failed to parse MlDsaKeyFormat proto")));
  }
}

TEST_P(MlDsaProtoSerializationTest, SerializeMlDsa65SignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
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

  MlDsaKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().ml_dsa_instance(),
              Eq(MlDsaInstance::ML_DSA_65));
}

TEST_P(MlDsaProtoSerializationTest, RoundTripMlDsa65SignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*parameters));
}

TEST_P(MlDsaProtoSerializationTest, ParsePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlDsaPrivateKey private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  google::crypto::tink::MlDsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  absl::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> expected_key =
      MlDsaPublicKey::Create(*expected_parameters, raw_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(MlDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlDsaPublicKey proto")));
}

TEST_P(MlDsaProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlDsaPrivateKey private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  google::crypto::tink::MlDsaPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(MlDsaProtoSerializationTest, SerializePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlDsaPrivateKey private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> key =
      MlDsaPublicKey::Create(*parameters, raw_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::MlDsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_dsa_instance(),
              Eq(MlDsaInstance::ML_DSA_65));
}

TEST_P(MlDsaProtoSerializationTest, RoundTripPublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlDsaPrivateKey private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> key =
      MlDsaPublicKey::Create(*parameters, raw_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key, IsOk());
  ASSERT_THAT(**parsed_key, Eq(*key));
}

TEST_P(MlDsaProtoSerializationTest, ParsePrivateKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  google::crypto::tink::MlDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlDsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_seed_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  absl::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> expected_public_key =
      MlDsaPublicKey::Create(*expected_parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> expected_private_key =
      MlDsaPrivateKey::Create(
          *expected_public_key,
          RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

TEST_P(MlDsaProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlDsaPrivateKey proto")));
}

TEST_P(MlDsaProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  google::crypto::tink::MlDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlDsaPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_seed_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(MlDsaProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlDsaParams params;
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  google::crypto::tink::MlDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlDsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_seed_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(MlDsaProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::MlDsaPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(private_seed_bytes));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().key_value(), Eq(public_key_bytes));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().ml_dsa_instance(),
              Eq(MlDsaInstance::ML_DSA_65));
}

TEST_P(MlDsaProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

TEST_P(MlDsaProtoSerializationTest, RoundTripPrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlDsaPrivateKey raw_private_key =
      GenerateMlDsa65PrivateKey(test_case.variant, test_case.id_requirement);
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  ASSERT_THAT(**parsed_key, Eq(*private_key));
}

TEST_F(MlDsaProtoSerializationTest, ParseGoldenPrivateKeyWorks) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  absl::string_view public_key_bytes_hex =
      "51a09ab1023acc98a397a0a019307fd3a3f43a8d3064197725e7fdc06d262dc92895483e"
      "81254addd9e72bfedd5e3d17497e079be5bd5d162838e3eabd6bc10c3e274d8bfaeaac99"
      "d1206fc20ecdb84d8ef3b3dfca8557a2218325b0de00733f7dbce7f255e50959e845d72b"
      "1ffe277c87de88bc75e239352f513830e74e3999428358c884d5578aee9be53bc54ae891"
      "91c758f58f43a0d03e8211270288022e01538159b071c4328882a9726c17263079ec1d98"
      "19d97fd39ba770ccf283cda1e2ff20f095e74479556483f5e9af8d98f206d0825c964f21"
      "5e18ccfcee6a1419b31c8d8e26e7b54fb6a87b488b8cb54e91177a431268e73f2417a3dc"
      "81140fca7c69c9c20b93faba91fc42e67fd017682f5589c64cd0c3d5b5a503d7fcfbe347"
      "46932cb0ccde62fdb42a6d3c8f3d493eed6625c25755b8b970b8dc6deb159930be575f23"
      "7fadfe3fd1af05b6bd4297979fc3af0d4e0503030c21e78b141aa24029cfd9807893a82f"
      "b33b8a91d6a8a94c67c7d380ef6a573c73be6ed605498440e23e2151ed87819b069992f2"
      "f7d2b24073efebdf51d5a1e67e16f837a12b3139d4e4f7a7d5c9214da83731e08a906118"
      "ee63e822da91f9ef9570538a78aa95649e5f829dc3095fbbaf31607b07d25ef7665adbde"
      "4fd4ac1ddb70cbd69e80564c7a72c6e58a1a429e4aeed2bdf7177d0e057f2ccaa2acf8ae"
      "ceee7fc20e609e0d6760abdbf4b5fea64e67b5620df677266b3cec53b8470e92fbbe02b1"
      "969b8ffa07d2191b6402102c18ed75b441c446a36ccb7be6b39693770ecf32067208ee06"
      "24ca7f6f5e702cdacaec9590a70c9a251ec977fa1fa9f8e5fe806de8acbfeb57310a721e"
      "c31aa1e903bdfb220c1e7021f89c47c0698e9edf8c6c6ff20df554855058baa83f9631bd"
      "31105ccbd953be038f6d23280bdd0e8506ba37da4463b2dc4a66015723ee4dfc44a9abab"
      "0f19f0597e7a76848e65aa5abd00d65f96704f5e3f8a1ccc112f23d2821d0244d72eb952"
      "d39ce0968c694e6e1640e76d20847fc5e2fd94574e7fa0047b4e60088d6f511224b92f56"
      "a30103db1771f2dd36d9d30cf937f80a04dbe3234dd3c716ccca8cd141f92ace71fa5290"
      "0e7c73874ce2e891b35081e7a4cabbdd61b3944931b5ec67744648d5a89daba3bcff0beb"
      "e759817dc009e5780fbd45553b5d5e562fd94a41e00cf0c4578468871ddec77a9f7cb301"
      "91dad5760974983e31488a24a412a44e885a8386fc16831b25c17edfb140ffc0112bd9ae"
      "decd3976655fafc681210efe44425341fd3ee458309ae350c0b96dbc50914e4712687a9d"
      "ffcfb435ab0597d5607934d4ea711ebc8feda87d8c14bebef69c7eaaa8c7742d0cdb295b"
      "d25795b7737b5d30503ef5e3dfc37973aebfc1935cc8d195c9f374cdba78d0fe871ad6cc"
      "fb9001ad35f9917ace444d6d448ab2b7357d61d78741d6e43b77cf6b8674d927af1aa426"
      "f668d0cf0ba0fd889362eb652f73b1d1be0dc6f86f0f4d4207473da9263829a3197f894e"
      "68130f1e02b2f8cbfcf24af5bb78be40e0f21220c93b53ba4a373429a8be89cfa03a24ac"
      "9cedacc0c378adf9e1f0107908254f7bb61afc81ca53f2d7c76972b8dea425f04bca595d"
      "a60ddffa49d00f70eeb8af13e35887bdc760beeda66baecf93a465375774ac50b2462d73"
      "2e6736c3de8733760fb583514ea32b74e097c8052fa089490b47170d2ece6ba39aca9cef"
      "939e582ab792679e82e3b9d8593193b2aa8ff11d4806da28bda27429a5c5a9d264986eec"
      "1cffafac707070a648096beff100c5890a7280eb71890f225c44025f17a51bc72b329f4c"
      "b7f1cae3b2561fc525e340cb8b86b545de4335aa45d9468e4b6e9c5b459eb0abc1c79523"
      "29e7b19e5ad83722d2dec2233b308b55a3c8af2dfd3f21accb28112dd05297cc934e963c"
      "c08fad897c32e223742052ac50f993b8de5d7966a32ab5a2107fbe0da9c09ebbd9c66b86"
      "e4286977976dd7539d34f7960bc94d7ccff98825dabdf51af3aed87f8653e71a5f19a635"
      "c54ef00d8e097d91e686d144fd6e9840d72c6c87d4acf497696f3ac91a94ddc6f88bd11d"
      "8c6a1bc209118ccabf565b82a3b6226440fd3b2eb9825128428c142ff7955d2c9c902a2c"
      "936db386b1c390440e32d1939256804b5c032368751a11bfa8be1742c4c44e32edc6ab2b"
      "00c519831c8e8ebcd0de15d0d752a3dc4b1845d5bfcf7b958aefa415241c05edcbb07a0c"
      "7dffdb7780576e4dd5ef564437a880567f07f6d0606aab2e8e71de453fdeb9469fa3fa79"
      "bc32218c01f6f7394969706b950afdd7afbcea0e0266ea4d5da76a96cd9970b014a8f35b"
      "fb30b255c938bc72c57cfe177932243a92b7e013847bafee10bc262dd77ffdd0d979c57c"
      "31a00a3cbcbff215212cdf407d45c9290ca894fa7f8b0792a8103d045ba9007e23823fe3"
      "efe264664b644fd92d7227d085494eb29acd1a619d1c7a6ee0ec0e083459d1986be6c426"
      "c57004298701825768b95477a9c279be47869b11d1568423c39e789862d15d3014239ec6"
      "15a1aa39e92e6a1c062fee26582675576b88a1fe4bed76e15d9f5fe4cf36b549220bb32d"
      "dc64400c6e0d99e39e47d9feca3f39d418c88e48b950b7fab7a36c7301e42c97e49d0a99"
      "812eaa10c3bb60e2e15e987d4009cf9468e28de331ba4d66103ef9b644d89a72300cc1e4"
      "012617a8bd4a4f958451da83bb8a64b2f09a8d5ac898693db9c36a92ab0530042d41111d"
      "5c1df76e8722a7cf";
  absl::string_view private_seed_bytes_hex =
      "84d1e8cb37e37dc5a172706588fd367a85e9b10669a791bff7a1d77c0661e379";
  absl::string_view serialized_key_hex =
      "1aa70f1a02080112a00f51a09ab1023acc98a397a0a019307fd3a3f43a8d3064197725e7"
      "fdc06d262dc92895483e81254addd9e72bfedd5e3d17497e079be5bd5d162838e3eabd6b"
      "c10c3e274d8bfaeaac99d1206fc20ecdb84d8ef3b3dfca8557a2218325b0de00733f7dbc"
      "e7f255e50959e845d72b1ffe277c87de88bc75e239352f513830e74e3999428358c884d5"
      "578aee9be53bc54ae89191c758f58f43a0d03e8211270288022e01538159b071c4328882"
      "a9726c17263079ec1d9819d97fd39ba770ccf283cda1e2ff20f095e74479556483f5e9af"
      "8d98f206d0825c964f215e18ccfcee6a1419b31c8d8e26e7b54fb6a87b488b8cb54e9117"
      "7a431268e73f2417a3dc81140fca7c69c9c20b93faba91fc42e67fd017682f5589c64cd0"
      "c3d5b5a503d7fcfbe34746932cb0ccde62fdb42a6d3c8f3d493eed6625c25755b8b970b8"
      "dc6deb159930be575f237fadfe3fd1af05b6bd4297979fc3af0d4e0503030c21e78b141a"
      "a24029cfd9807893a82fb33b8a91d6a8a94c67c7d380ef6a573c73be6ed605498440e23e"
      "2151ed87819b069992f2f7d2b24073efebdf51d5a1e67e16f837a12b3139d4e4f7a7d5c9"
      "214da83731e08a906118ee63e822da91f9ef9570538a78aa95649e5f829dc3095fbbaf31"
      "607b07d25ef7665adbde4fd4ac1ddb70cbd69e80564c7a72c6e58a1a429e4aeed2bdf717"
      "7d0e057f2ccaa2acf8aeceee7fc20e609e0d6760abdbf4b5fea64e67b5620df677266b3c"
      "ec53b8470e92fbbe02b1969b8ffa07d2191b6402102c18ed75b441c446a36ccb7be6b396"
      "93770ecf32067208ee0624ca7f6f5e702cdacaec9590a70c9a251ec977fa1fa9f8e5fe80"
      "6de8acbfeb57310a721ec31aa1e903bdfb220c1e7021f89c47c0698e9edf8c6c6ff20df5"
      "54855058baa83f9631bd31105ccbd953be038f6d23280bdd0e8506ba37da4463b2dc4a66"
      "015723ee4dfc44a9abab0f19f0597e7a76848e65aa5abd00d65f96704f5e3f8a1ccc112f"
      "23d2821d0244d72eb952d39ce0968c694e6e1640e76d20847fc5e2fd94574e7fa0047b4e"
      "60088d6f511224b92f56a30103db1771f2dd36d9d30cf937f80a04dbe3234dd3c716ccca"
      "8cd141f92ace71fa52900e7c73874ce2e891b35081e7a4cabbdd61b3944931b5ec677446"
      "48d5a89daba3bcff0bebe759817dc009e5780fbd45553b5d5e562fd94a41e00cf0c45784"
      "68871ddec77a9f7cb30191dad5760974983e31488a24a412a44e885a8386fc16831b25c1"
      "7edfb140ffc0112bd9aedecd3976655fafc681210efe44425341fd3ee458309ae350c0b9"
      "6dbc50914e4712687a9dffcfb435ab0597d5607934d4ea711ebc8feda87d8c14bebef69c"
      "7eaaa8c7742d0cdb295bd25795b7737b5d30503ef5e3dfc37973aebfc1935cc8d195c9f3"
      "74cdba78d0fe871ad6ccfb9001ad35f9917ace444d6d448ab2b7357d61d78741d6e43b77"
      "cf6b8674d927af1aa426f668d0cf0ba0fd889362eb652f73b1d1be0dc6f86f0f4d420747"
      "3da9263829a3197f894e68130f1e02b2f8cbfcf24af5bb78be40e0f21220c93b53ba4a37"
      "3429a8be89cfa03a24ac9cedacc0c378adf9e1f0107908254f7bb61afc81ca53f2d7c769"
      "72b8dea425f04bca595da60ddffa49d00f70eeb8af13e35887bdc760beeda66baecf93a4"
      "65375774ac50b2462d732e6736c3de8733760fb583514ea32b74e097c8052fa089490b47"
      "170d2ece6ba39aca9cef939e582ab792679e82e3b9d8593193b2aa8ff11d4806da28bda2"
      "7429a5c5a9d264986eec1cffafac707070a648096beff100c5890a7280eb71890f225c44"
      "025f17a51bc72b329f4cb7f1cae3b2561fc525e340cb8b86b545de4335aa45d9468e4b6e"
      "9c5b459eb0abc1c7952329e7b19e5ad83722d2dec2233b308b55a3c8af2dfd3f21accb28"
      "112dd05297cc934e963cc08fad897c32e223742052ac50f993b8de5d7966a32ab5a2107f"
      "be0da9c09ebbd9c66b86e4286977976dd7539d34f7960bc94d7ccff98825dabdf51af3ae"
      "d87f8653e71a5f19a635c54ef00d8e097d91e686d144fd6e9840d72c6c87d4acf497696f"
      "3ac91a94ddc6f88bd11d8c6a1bc209118ccabf565b82a3b6226440fd3b2eb9825128428c"
      "142ff7955d2c9c902a2c936db386b1c390440e32d1939256804b5c032368751a11bfa8be"
      "1742c4c44e32edc6ab2b00c519831c8e8ebcd0de15d0d752a3dc4b1845d5bfcf7b958aef"
      "a415241c05edcbb07a0c7dffdb7780576e4dd5ef564437a880567f07f6d0606aab2e8e71"
      "de453fdeb9469fa3fa79bc32218c01f6f7394969706b950afdd7afbcea0e0266ea4d5da7"
      "6a96cd9970b014a8f35bfb30b255c938bc72c57cfe177932243a92b7e013847bafee10bc"
      "262dd77ffdd0d979c57c31a00a3cbcbff215212cdf407d45c9290ca894fa7f8b0792a810"
      "3d045ba9007e23823fe3efe264664b644fd92d7227d085494eb29acd1a619d1c7a6ee0ec"
      "0e083459d1986be6c426c57004298701825768b95477a9c279be47869b11d1568423c39e"
      "789862d15d3014239ec615a1aa39e92e6a1c062fee26582675576b88a1fe4bed76e15d9f"
      "5fe4cf36b549220bb32ddc64400c6e0d99e39e47d9feca3f39d418c88e48b950b7fab7a3"
      "6c7301e42c97e49d0a99812eaa10c3bb60e2e15e987d4009cf9468e28de331ba4d66103e"
      "f9b644d89a72300cc1e4012617a8bd4a4f958451da83bb8a64b2f09a8d5ac898693db9c3"
      "6a92ab0530042d41111d5c1df76e8722a7cf122084d1e8cb37e37dc5a172706588fd367a"
      "85e9b10669a791bff7a1d77c0661e379";

  RestrictedData serialized_key = RestrictedData(
      test::HexDecodeOrDie(serialized_key_hex), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(0x03050709));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(), true);

  absl::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<MlDsaPublicKey> expected_public_key = MlDsaPublicKey::Create(
      *expected_parameters, test::HexDecodeOrDie(public_key_bytes_hex),
      0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<MlDsaPrivateKey> expected_private_key =
      MlDsaPrivateKey::Create(
          *expected_public_key,
          RestrictedData(test::HexDecodeOrDie(private_seed_bytes_hex),
                         InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
