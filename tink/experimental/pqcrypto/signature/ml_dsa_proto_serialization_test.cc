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

#include "tink/experimental/pqcrypto/signature/ml_dsa_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/signature/internal/ml_dsa_test_util.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_private_key.h"
#include "tink/experimental/pqcrypto/signature/ml_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/experimental/pqcrypto/ml_dsa.pb.h"
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
  util::StatusOr<MlDsaParameters> parameters =
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65, variant);
  CHECK_OK(parameters);

  util::StatusOr<MlDsaPrivateKey> private_key =
      internal::GenerateMlDsaPrivateKey(*parameters, id_requirement);
  CHECK_OK(private_key);

  return *private_key;
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

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
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

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
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

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
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
  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MlDsaKeyFormat proto is missing params")));
}

TEST_F(MlDsaProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  MlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_65);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine MlDsaParameters::Variant")));
}

TEST_F(MlDsaProtoSerializationTest, ParseParametersWithUnkownInstanceFails) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  MlDsaKeyFormat key_format_proto;
  MlDsaParams& params = *key_format_proto.mutable_params();
  params.set_ml_dsa_instance(MlDsaInstance::ML_DSA_UNKNOWN_INSTANCE);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine MlDsaParameters::Instance")));
}

TEST_P(MlDsaProtoSerializationTest, SerializeMlDsa65SignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
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

  MlDsaKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().ml_dsa_instance(),
              Eq(MlDsaInstance::ML_DSA_65));
}

TEST_P(MlDsaProtoSerializationTest, RoundTripMlDsa65SignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
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

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  util::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> expected_key =
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

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
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

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
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

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> key =
      MlDsaPublicKey::Create(*parameters, raw_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
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

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> key =
      MlDsaPublicKey::Create(*parameters, raw_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  util::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> expected_public_key =
      MlDsaPublicKey::Create(*expected_parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> expected_private_key =
      MlDsaPrivateKey::Create(
          *expected_public_key,
          RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

TEST_P(MlDsaProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          test_case.output_prefix_type, test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
  EXPECT_THAT(proto_key.key_value(), Eq(private_key_bytes));
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlDsaParameters> parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> public_key =
      MlDsaPublicKey::Create(*parameters, public_key_bytes,
                             test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> private_key = MlDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());
  ASSERT_THAT(**parsed_key, Eq(*private_key));
}

TEST_F(MlDsaProtoSerializationTest, ParseGoldenPrivateKeyWorks) {
  ASSERT_THAT(RegisterMlDsaProtoSerialization(), IsOk());

  absl::string_view public_key_bytes_hex =
      "71c7c5f51f797c3ff2a1a069cbe636ec81e6fbf9593505f3886d6ce7ad316406171ecfc5"
      "f9364f87db687a169015d962ccba277ee2cd62a40dc698bf20a65f13596baac1d337f7c5"
      "b84c502af2c305f65ddc2988359856da0616757d2d371c02540960d6a7eeb4905d45684e"
      "ed210b673d97b8e215226b69d7bcf3e5f5a51404186793714843b7de9391b6ab18a5f6ab"
      "5d69c520bc718a1add127d27164b6cfa42b3eeb06f3dbf0b22b6a303209414b52e438d41"
      "7057cf551321256c2ebc47988fc06ec691c64de2288ccafc2fae2c6a10438479c6a2d676"
      "3ce8232e11546b10c1e0546846fd56c2b0ff3989fd1f471bcccb25a47db07191962dd042"
      "942577cb2f7a6e9fa399ebb58e737098e4aedd725125ec57b9367570c418a9d2560b511c"
      "9f1018bdcc16f9f95d4d6dd51799cae251fd656e27357f22e7b3a29faf3aa44f575f35fe"
      "46282b62871d8cdd815b712fcbe0588f0bf707f858d6e1c52240cf8508c45ad31d090d75"
      "3ad6bfbe4aaaa9f61b30c71ee4b8ac599c767a4d657551eb4f7edd4446b7ec76917b6a5e"
      "e057d0433d90bd99f1ce57d375e086efe958c8c33531d6df76bdd50f6a256063edb0910d"
      "ad11d7d931ab80029f2efaa3cd820429bf694573d2e05ff0b0f3dc4b6a3b8ff3df03713f"
      "23846a864a2d834c8370c1a416f010b58db720471857ba14b4dd57b6709c6290a6aaeebd"
      "fed62900f3b039ef53ae2930df40bb5d5293f806bb550dd0e98bbeeb018d2027d468d68e"
      "dc451702e11e1eb8de3435ad36fb327c6d5385f3cd57805b4512ea66fda577e4738bb870"
      "97b2979c5bcc38e18fb8fb4b47555167fe2302359d4427dcd15f5ae02dc705758e4a879b"
      "61531b30f1923c21242922962eaac9cf062b8683cefeaa0ef00270905c0ce1148cf7730a"
      "0bf6f3c1bf20e257a35ecfc67cba4b6083f15b4bc39a38abe6ba488183e2ee3016fdc69a"
      "d1003607c1f0909f7c61041f7bf34397b565f31ef3aaace63f214edffb94122632cc54e9"
      "0f1712ae6d13ad22cac508b49340657f3d2694cb41b41860a27c1b89b98957def3101b0f"
      "151dd22c089b96eaf27c0fd28dde0273efca5b57b37cf2aa3ef5b7c1a1ab65e104109390"
      "cbeb28cb6db3bcedcfe8a4b090781b58c621ce5b4ae2b68af768701f7bc4e391e2fb248e"
      "6369d87ed40d439584c59f1e96c67496c5b73e12b5729e49332505368cc83c2c8744a3db"
      "b119bf1d8705f4ea4136ae1c226135759063377089d77b7ae0efac33767445378e3d8a6e"
      "0aa1ae1aefa5f529ee48b78a8e521bc6023ce84bbd7a5b80fc723025275d9426dd87fa21"
      "0da80a6f37e9ca8eafdcc52993cde3ce8f3e7190373422b2273183c9704356f136b39b7c"
      "15128b40fc2e911282f8fc9495410a4514d0139dc4d78fd24982e5944102955c6aa31223"
      "e050e87528de34ebaee5941515e665a078502c6e268f871e476e5c4d9152172a40d23a12"
      "cd87bd64f40dcd737773dac0f4088b4cc4d5759d1fa0650910347d6f13ef90a80cc807ac"
      "beb9945b57103b1fefd8a343c1f6106d25f4c49d735f9ce947d224d9d0fb8a1a8f80560a"
      "519389bfb4dad30f120857cbaa426d4b63af32722d99fb8100f32965dabb232de6036f68"
      "5b3d0fae91f998dd81f9bc6c295aac785ca70e042a8ece6a9d8b050c309a8a9fa2cb5b3b"
      "5739b85d33a1d11caf1f006c57743916a6d38c3b61f55cf03bee8d2b090ede6da094cf22"
      "580b1684db52f05f4624b9a038f1104f153f8d9263e456f483de5b083b3240f5eabd08cd"
      "301addc1c1a9c33be791cbb59bfe28cf398d1ee2f6b4509b18b4a7ad9321acdb6b0c7065"
      "be1ba4320f4a2aef551ce19b282e7a7b053ca9f8e6f72ad33765a816d0364aa3d852d1c6"
      "fd808541928fbeba1a058ebcccbefadd92c2febac1e44eadb301739833055d67a098eaaa"
      "8a9fafb12da1195216c964c5e79ca8b80568cf77e549f8e167ad5364b5d3eeb9bd344eab"
      "6807382fbf58da1f7d21f2f6aa6f5013d4c4f1f3cf5c2138fb8d02908fb4ea7d3ca240b2"
      "8db04c29d64ab1a239e30e59c92c981ab1f7b3e63ebd5979710c4a8f5f3afc203a7e55f5"
      "aeb450c198623a486b45121bcf6c5770074b393cafc962e1da41f2bdf923370319ee415b"
      "7d2110cbe0b638e46fad935db55213f75f971a72e6e95f452836bda468683c47c96bc620"
      "a78c3148c56aabce9556d4b2d593fa2ede2c22963f02ce1d8c18436ded59261a77313b35"
      "aeb37a689a121dcf89ef0181ceb54a62f780bae1e834fcc8e1a107e8586cdde2750c4f7b"
      "b9acd50bf2af5da40ea26cf20d77c011910e262ca68f3a4ad11c424208f73ba78075f7bc"
      "c6acdd2ba18b051d86878eb77e8c77a6752ffac9c3a3035e29a602c0401183694b3d5d98"
      "86d1a214adee68bfe5f21ffaf2524b0373f1ae4f7bb45c4af97bc269d7316bb17feea458"
      "c19484efd55675f3b5b162e1f54d42024e9e83669e9f69d7d6c7c3f16b8e396230980723"
      "4ea8d87e3c87152dbc879c7097d4a2dfe9bd01c2a06e93ec978750603c01fe890eabda5d"
      "62220a4bde9db0c432b440d34fa4daf1c3286c08dc8754882c4186049a00ca0881a42409"
      "1b889cc8936f29aa8b0d5474dde9070d7f3c31985c2cf38b318bdacff9a3f027c414ec79"
      "b8887d83bc7a47da04289eaaeb624db3de5e8b2cf1edfa38fe2fc357b13a1f3ba036f731"
      "fddb061378bce10a2df0c61f1f57d6914e663ae60315da9282c29afb7d027d428c11819b"
      "0d86d0e8d201ffb4";
  absl::string_view private_key_bytes_hex =
      "71c7c5f51f797c3ff2a1a069cbe636ec81e6fbf9593505f3886d6ce7ad3164065dbc189a"
      "1cf88032ca529d541bac05cf00311ab032fe0f9e1fff015816b17663e5865742162d7245"
      "ebb1ce080b533a33fe09129ddb040157f767a2ff3447ad3fca335edb92c317a6543a82dc"
      "90ee8c670d6a2cbe9f32aa523d6ff823f2b6cac036224044654565024304427575383324"
      "528778017675777515375222176588736547842104124016833065361338406583215028"
      "156410533730273777825056378573421084033504513170385760181355257685337758"
      "662255011304281111153273167508678720013007533765602010352273377174265000"
      "137576168688522065874160268323846202567018755347644103148523517682868058"
      "583122006701088203374353128442272545502866310373363738627808148054610724"
      "087454202756278071221404300106321331166462158731120163855083402362683474"
      "518331861181808515510086148875748138313654763533723574357557348001130428"
      "762674781553721744477161706441005455854443838674760382738250120080760730"
      "464663300841555677366736676345676103162557152170311128110156831502504860"
      "063620302806581683346232058100710862535208467368351374808125228360853145"
      "404182328764306463006146271681221561351862154274345021700876706246444868"
      "801834585043661861775828676614840708076207324662228108682737207223151011"
      "674127705352470161728746757384245546662167827756202115251305823503846155"
      "646178245107204830474680817603400688335652130050352246077730741468640810"
      "768524253010742885622601700135581758042581056878028132815562555240008720"
      "557541535087711262722518111223583320011713450563476282822603877564358445"
      "585036282526058580865600156542367136676221132384454871078456756458161533"
      "350463107717634251115237720314203474445726445265688011223861601376152033"
      "806477831672025583121343115745521416344017816803144012075034546666327031"
      "413527421026476334545871171457480486362815205080030831064166828520724684"
      "516524742568152155460485622607684883843225357711348716721015641118838144"
      "686605102013037340525104138067785147657147243054463268605003184700601345"
      "500770622768004588587532456754588352706547803387602205871183727674124017"
      "325620083734453072774247052580187121484651562622151848547040854138303866"
      "005002730120882007705327018187563845617023223300461207258407251226805525"
      "877552771425502888468312464656710114083047468118643528043735507314882721"
      "778238400282785760510403636150500675512568261335737550835141754510866300"
      "685800351601023780605700277075272856762160856423872425838706016024874514"
      "248752821741742535803266118431345531001388531820336851087851287435754443"
      "312415286205380107800507852163317208113104563550420383816708378186272136"
      "682416168833174168663318845035724235216780164433503674805304348013202551"
      "036348702300403008246848886776876554273362678772641358230016605665524367"
      "282437112413834201230082123821337667405787473682377386203187145242208750"
      "373207821451352643020230301226822281617151753565638000085070363302271123"
      "602386238515678881428826820221630261507556732748488221171713335602024883"
      "004133538688337526737782505783064251747864011388780640760883238203534405"
      "407176436485824042514801422313140517786317274874845481583136836517180867"
      "268277737360224686632218881806546751186410104767741511671063741001753352"
      "005876122016173135444187817386856782105218631548515f3d43c213c2249e6d62d1"
      "254c67cb662bae5d1c7ce497aa9d5bdf20c84b104cf692cec4cf668066ac2c9356513994"
      "10bf3d00568ecc92b4aef7267112c53ee162ef895d72b57796d8978f6549d62b0935b1d7"
      "c7c4ca2b7f5f01a9a512af0e579cef5befb214af8a6e8989d7c099be4222c55068afd414"
      "b1a579b788d34fdc93bdeb2f43c4b9ef81409feb28918cc14838736f8bd1d663ec6c8b04"
      "cbc5a770966c14217c5201d4c2033171483d546643af447886173fb12c48ac1c9146b3e2"
      "eecbdc918288d44cbb12e0f1ac48cf61e6b2912e5303bcd7570208220459e6c4b30a3dd6"
      "59e3a7b2219d5e1d15515c08fe348b4b8feae2d09baee32b6b029212a4fd69be1e7106aa"
      "685cdf990ee9bef1f639b183d547056ce196f9f4dc0045b5a00880503ef10d1681234a82"
      "47e40db01ce8e4feb4f5834704a25665c3b36118fa0b5ee17ebe3848bac7cab4ac1339b7"
      "a6142db0e0445f1968a1b5f692a3493c8c40bb9cfb4a918916448425abefde587917a9d5"
      "6155c7946bcbe0b5b945d55508cc8e426404736816b7d4faa1ad202206d763afe5c9a059"
      "2fb20929e916f6637a1c7799ffdfc964b7bc21d055ce1dd1e836139065984ce4d5f91efa"
      "3d33e0be043390872590d803b4f78de5038de77b6c8750a42437255245d999d6ddcab47a"
      "dcd9a9c21e96344b838a6adf0d12495f78386f1990bc298100163d276082f997bef6f91c"
      "d5468b1a5e5f6427a7dabeacbdf9136bf3d943f7c916c0fdffa7cbf8ceb5de2f4416cd67"
      "42e7dcaa47ea70965c58d2d547d2ec640c54147fbd6e602cbf2b65f08aaee344357c655b"
      "bd3d5d412ee575317785e75306c560b6dbe1c3b0c914b5715764f4815d6b9c1da090414b"
      "dcb646045cc906c123409177412c020a906fafe2b17006c08d81392a10c80dea978dac69"
      "cc75f2a0b1692b57498e4e68137f02100aba475627df4963876049e3b4caa9a02ad60a50"
      "07400bfdef91eb5d8d62ec596d73a157d5b49cf31839e52867d4c17fa45014bd64997478"
      "3aaa1edbd8604ec2a1f8f67aff144d808992d3858736baa6b9d731dea2acbe18ec5da9b1"
      "d3d50dcdb953bc8a12ad9dddf6a629e66a61486038c0baefefa902fa0e3b88e200c82edc"
      "665075f247bf81b50348932b4e7a1031d4166ccb3b9c480a20425c9be869d9dace1eb248"
      "4be8a3627e18467c43f51f732cbdc8f816654e77ed3eb0f5bb7c4bb4c2738bbc645598dc"
      "cc6bbdb595ca958498f11d12139f0648de900e15a71e68a86861ba44fa26b9ed7c7a2592"
      "2a71f896041afe84b99b0ed0fa626e34ca332ad5c07cdcb2581c2c9863b760cdd475515d"
      "1a9b031a231f71a28efaa88e18dca2f959fbe66ea3ca956e2c835d6e279932e1a16f3d00"
      "eac35a2ad9e86cd56721c927799947b6c5de3445be843cf805a833af1dfa72b776ac7641"
      "2e0c23cb3003f81ca7babc40e5220da894504f2bbdbb298bde76829cc136cfc978945b14"
      "011402f04ec743b58f1a696b01940cfc60f8cd9aa6e49cf61454d380a1fc977a041ef614"
      "4e5ddec8e0acbd9e9e56635160263682c1be1036b59295334043cdb88fd851d90fa6537e"
      "384dcb9af2cc04c6c618300705660b73f4e571248b7b83044b1d8cf6a828ae2dd674bc42"
      "c53e5c03556f718dddb9748eb8041e46e30bcf27b111950aea824751ab3704158ae27419"
      "06b8c18c84edc891b6e80c1a034d4046660deef767669ba14c6c6b4e2bea0180abc8e592"
      "87328b4d1e217425159534e5e9f1039e4987e0b63dc83d96a7ed3519f065d4321c97962f"
      "8afc7ce6552823ca36e7c8fed66f8c40d8d4020eede2c4a885db32750c7b88657e308a88"
      "cd4f0d5dd1c5188c816e115ca90f6dd659141df83aab96333994d18456ae880a7463ceb2"
      "e8c506dc665dffa0a8337810075461ca0efd56734b003c79145afc031c55c4d33169cf6e"
      "28403874dcf9ab8c1bac86863d93d64311cb6e1a3ca1456845973b452d642c4b47094f0b"
      "4251af36c23c3aa24fc4765236753fa2668931e0e6bd5496039949aeea94661e4ff4f214"
      "6f5db927a1932490e421190c1020efd8b4051833d409135332c97c29393bec703e37a778"
      "b6bc6512fbf95ef2ada4c42bbe6ff6c69b9016ce49fec63f46db5b7b80c0ae91f190a2c5"
      "96f0cb9a3511c72c4ff1835c72100d616b8ea683e73cdc45b76994b4be31c39d4debe451"
      "18323662fbd82cf0ac701df285245dd9f6177489fc13a4e1712dd6f04624b92989c5b345"
      "49c4d57521cb7dcb9794aa4e8de502ab063662cac0c0d54c1911055cb8209735bdd6faeb"
      "86f0ecf1a65a3e49431c47cf1260e2efcf5274e656f06733bfb4fb243ce5ad48834932a9"
      "f47458ab02ed516b849d04747ce6fa32cbbc0cfe94f9f3d94af760049d5c60b999a328e3"
      "f200500692c718258086ae7c2015b5fe7925925cb5784397b0f321cda79255feb9b55fe8"
      "ad234f87841832829f98fe8b43721a6de3a9acb8a4e118a97262b4e623192584123a39a2"
      "4701be68c7ee0717eca236282e925928ea5aa7cb1aec245691da0f7149ce5e2c6b018172"
      "dcf5672489e7f880408e477e56a773da5cd6d2caf5e78d3c03ed5490479b5c123e36a4cb"
      "fcd017655b5215f59d504b0a3a0b2836102e41ca5bf5ed019becdbe323b2c0f3322538bc"
      "0dbe8bb54e74b74e900d08cff3e26a4f03d3bedb27deb72d270007a7c82ecdff314308a1"
      "0a28794c5550a35be5226c554e80614e41df1668ac7b98217c384e3215e6cac5d1b8ef4b"
      "600ef974099b8b5a594e03a56866b542377c490ea95175327c60669b763cd1164a967c60"
      "d1270cb6652781200d26d33750641f2ea8151108251b0608e2f6112fc6c3bfb5d937e69c"
      "8e53e68b154288070e444cf02b4d57346235987657ee3b782b60a3a665f76d821fdf987b"
      "590d7ff079a99621a04d8aff113b05f1e73805fc0ab40fee96b7b5edc5c4f94646adefed"
      "170c9c6f231fc660c670e124b675df92ea12a0a4b06886cbb7ff554a6da89a4027fba6ef"
      "5c4ac45bf36ba974fa30110c75ab3d38b37698168bcfacbc2b8964746adbe99219852e8c"
      "0717d20fdbe4d8400ef608c5c5c22fa22c02b50a890bac4b063bf86bfd07531f9604c7d1"
      "5e39c599ff869b937017572500409e958fda3c1cd7b5755e2dbd37fcd895c28d6d922679"
      "f7f32087224568e051b0b7ab1c9ad159b55e61660e53c6a065d4061ff443c5980f0df916"
      "9ff426d849a69d1b7bf0adcef23d98674f7325f73521496abd4796559325e37aa720b12c"
      "c974dbd1bc6f8ad55475741e0f9d42af9087cf840b17161cbbda2b815c3757111bbc8845"
      "54a21eb6827f1289b234e72a53d5d5acad9488c0ff944a646b40e38eec67ca6df8450b7e"
      "978114c7ca97200afc5a11b0a04ab19247725a3f421716b3a561cfe31cf2538e6406ef2e"
      "0ed395f4dd9387f3c089f806cae388974cb00ba004a97815a40fba8c114a03e557da5d25"
      "36e768432d0ed48ea0523acc434024c7599c7c822acdbeb1ea8672386b006a0da70c87e"
      "d";
  absl::string_view serialized_key_hex =
      "1aa70f1a02080112a00f71c7c5f51f797c3ff2a1a069cbe636ec81e6fbf9593505f3886d"
      "6ce7ad316406171ecfc5f9364f87db687a169015d962ccba277ee2cd62a40dc698bf20a6"
      "5f13596baac1d337f7c5b84c502af2c305f65ddc2988359856da0616757d2d371c025409"
      "60d6a7eeb4905d45684eed210b673d97b8e215226b69d7bcf3e5f5a51404186793714843"
      "b7de9391b6ab18a5f6ab5d69c520bc718a1add127d27164b6cfa42b3eeb06f3dbf0b22b6"
      "a303209414b52e438d417057cf551321256c2ebc47988fc06ec691c64de2288ccafc2fae"
      "2c6a10438479c6a2d6763ce8232e11546b10c1e0546846fd56c2b0ff3989fd1f471bcccb"
      "25a47db07191962dd042942577cb2f7a6e9fa399ebb58e737098e4aedd725125ec57b936"
      "7570c418a9d2560b511c9f1018bdcc16f9f95d4d6dd51799cae251fd656e27357f22e7b3"
      "a29faf3aa44f575f35fe46282b62871d8cdd815b712fcbe0588f0bf707f858d6e1c52240"
      "cf8508c45ad31d090d753ad6bfbe4aaaa9f61b30c71ee4b8ac599c767a4d657551eb4f7e"
      "dd4446b7ec76917b6a5ee057d0433d90bd99f1ce57d375e086efe958c8c33531d6df76bd"
      "d50f6a256063edb0910dad11d7d931ab80029f2efaa3cd820429bf694573d2e05ff0b0f3"
      "dc4b6a3b8ff3df03713f23846a864a2d834c8370c1a416f010b58db720471857ba14b4dd"
      "57b6709c6290a6aaeebdfed62900f3b039ef53ae2930df40bb5d5293f806bb550dd0e98b"
      "beeb018d2027d468d68edc451702e11e1eb8de3435ad36fb327c6d5385f3cd57805b4512"
      "ea66fda577e4738bb87097b2979c5bcc38e18fb8fb4b47555167fe2302359d4427dcd15f"
      "5ae02dc705758e4a879b61531b30f1923c21242922962eaac9cf062b8683cefeaa0ef002"
      "70905c0ce1148cf7730a0bf6f3c1bf20e257a35ecfc67cba4b6083f15b4bc39a38abe6ba"
      "488183e2ee3016fdc69ad1003607c1f0909f7c61041f7bf34397b565f31ef3aaace63f21"
      "4edffb94122632cc54e90f1712ae6d13ad22cac508b49340657f3d2694cb41b41860a27c"
      "1b89b98957def3101b0f151dd22c089b96eaf27c0fd28dde0273efca5b57b37cf2aa3ef5"
      "b7c1a1ab65e104109390cbeb28cb6db3bcedcfe8a4b090781b58c621ce5b4ae2b68af768"
      "701f7bc4e391e2fb248e6369d87ed40d439584c59f1e96c67496c5b73e12b5729e493325"
      "05368cc83c2c8744a3dbb119bf1d8705f4ea4136ae1c226135759063377089d77b7ae0ef"
      "ac33767445378e3d8a6e0aa1ae1aefa5f529ee48b78a8e521bc6023ce84bbd7a5b80fc72"
      "3025275d9426dd87fa210da80a6f37e9ca8eafdcc52993cde3ce8f3e7190373422b22731"
      "83c9704356f136b39b7c15128b40fc2e911282f8fc9495410a4514d0139dc4d78fd24982"
      "e5944102955c6aa31223e050e87528de34ebaee5941515e665a078502c6e268f871e476e"
      "5c4d9152172a40d23a12cd87bd64f40dcd737773dac0f4088b4cc4d5759d1fa065091034"
      "7d6f13ef90a80cc807acbeb9945b57103b1fefd8a343c1f6106d25f4c49d735f9ce947d2"
      "24d9d0fb8a1a8f80560a519389bfb4dad30f120857cbaa426d4b63af32722d99fb8100f3"
      "2965dabb232de6036f685b3d0fae91f998dd81f9bc6c295aac785ca70e042a8ece6a9d8b"
      "050c309a8a9fa2cb5b3b5739b85d33a1d11caf1f006c57743916a6d38c3b61f55cf03bee"
      "8d2b090ede6da094cf22580b1684db52f05f4624b9a038f1104f153f8d9263e456f483de"
      "5b083b3240f5eabd08cd301addc1c1a9c33be791cbb59bfe28cf398d1ee2f6b4509b18b4"
      "a7ad9321acdb6b0c7065be1ba4320f4a2aef551ce19b282e7a7b053ca9f8e6f72ad33765"
      "a816d0364aa3d852d1c6fd808541928fbeba1a058ebcccbefadd92c2febac1e44eadb301"
      "739833055d67a098eaaa8a9fafb12da1195216c964c5e79ca8b80568cf77e549f8e167ad"
      "5364b5d3eeb9bd344eab6807382fbf58da1f7d21f2f6aa6f5013d4c4f1f3cf5c2138fb8d"
      "02908fb4ea7d3ca240b28db04c29d64ab1a239e30e59c92c981ab1f7b3e63ebd5979710c"
      "4a8f5f3afc203a7e55f5aeb450c198623a486b45121bcf6c5770074b393cafc962e1da41"
      "f2bdf923370319ee415b7d2110cbe0b638e46fad935db55213f75f971a72e6e95f452836"
      "bda468683c47c96bc620a78c3148c56aabce9556d4b2d593fa2ede2c22963f02ce1d8c18"
      "436ded59261a77313b35aeb37a689a121dcf89ef0181ceb54a62f780bae1e834fcc8e1a1"
      "07e8586cdde2750c4f7bb9acd50bf2af5da40ea26cf20d77c011910e262ca68f3a4ad11c"
      "424208f73ba78075f7bcc6acdd2ba18b051d86878eb77e8c77a6752ffac9c3a3035e29a6"
      "02c0401183694b3d5d9886d1a214adee68bfe5f21ffaf2524b0373f1ae4f7bb45c4af97b"
      "c269d7316bb17feea458c19484efd55675f3b5b162e1f54d42024e9e83669e9f69d7d6c7"
      "c3f16b8e3962309807234ea8d87e3c87152dbc879c7097d4a2dfe9bd01c2a06e93ec9787"
      "50603c01fe890eabda5d62220a4bde9db0c432b440d34fa4daf1c3286c08dc8754882c41"
      "86049a00ca0881a424091b889cc8936f29aa8b0d5474dde9070d7f3c31985c2cf38b318b"
      "dacff9a3f027c414ec79b8887d83bc7a47da04289eaaeb624db3de5e8b2cf1edfa38fe2f"
      "c357b13a1f3ba036f731fddb061378bce10a2df0c61f1f57d6914e663ae60315da9282c2"
      "9afb7d027d428c11819b0d86d0e8d201ffb412c01f71c7c5f51f797c3ff2a1a069cbe636"
      "ec81e6fbf9593505f3886d6ce7ad3164065dbc189a1cf88032ca529d541bac05cf00311a"
      "b032fe0f9e1fff015816b17663e5865742162d7245ebb1ce080b533a33fe09129ddb0401"
      "57f767a2ff3447ad3fca335edb92c317a6543a82dc90ee8c670d6a2cbe9f32aa523d6ff8"
      "23f2b6cac036224044654565024304427575383324528778017675777515375222176588"
      "736547842104124016833065361338406583215028156410533730273777825056378573"
      "421084033504513170385760181355257685337758662255011304281111153273167508"
      "678720013007533765602010352273377174265000137576168688522065874160268323"
      "846202567018755347644103148523517682868058583122006701088203374353128442"
      "272545502866310373363738627808148054610724087454202756278071221404300106"
      "321331166462158731120163855083402362683474518331861181808515510086148875"
      "748138313654763533723574357557348001130428762674781553721744477161706441"
      "005455854443838674760382738250120080760730464663300841555677366736676345"
      "676103162557152170311128110156831502504860063620302806581683346232058100"
      "710862535208467368351374808125228360853145404182328764306463006146271681"
      "221561351862154274345021700876706246444868801834585043661861775828676614"
      "840708076207324662228108682737207223151011674127705352470161728746757384"
      "245546662167827756202115251305823503846155646178245107204830474680817603"
      "400688335652130050352246077730741468640810768524253010742885622601700135"
      "581758042581056878028132815562555240008720557541535087711262722518111223"
      "583320011713450563476282822603877564358445585036282526058580865600156542"
      "367136676221132384454871078456756458161533350463107717634251115237720314"
      "203474445726445265688011223861601376152033806477831672025583121343115745"
      "521416344017816803144012075034546666327031413527421026476334545871171457"
      "480486362815205080030831064166828520724684516524742568152155460485622607"
      "684883843225357711348716721015641118838144686605102013037340525104138067"
      "785147657147243054463268605003184700601345500770622768004588587532456754"
      "588352706547803387602205871183727674124017325620083734453072774247052580"
      "187121484651562622151848547040854138303866005002730120882007705327018187"
      "563845617023223300461207258407251226805525877552771425502888468312464656"
      "710114083047468118643528043735507314882721778238400282785760510403636150"
      "500675512568261335737550835141754510866300685800351601023780605700277075"
      "272856762160856423872425838706016024874514248752821741742535803266118431"
      "345531001388531820336851087851287435754443312415286205380107800507852163"
      "317208113104563550420383816708378186272136682416168833174168663318845035"
      "724235216780164433503674805304348013202551036348702300403008246848886776"
      "876554273362678772641358230016605665524367282437112413834201230082123821"
      "337667405787473682377386203187145242208750373207821451352643020230301226"
      "822281617151753565638000085070363302271123602386238515678881428826820221"
      "630261507556732748488221171713335602024883004133538688337526737782505783"
      "064251747864011388780640760883238203534405407176436485824042514801422313"
      "140517786317274874845481583136836517180867268277737360224686632218881806"
      "546751186410104767741511671063741001753352005876122016173135444187817386"
      "856782105218631548515f3d43c213c2249e6d62d1254c67cb662bae5d1c7ce497aa9d5b"
      "df20c84b104cf692cec4cf668066ac2c935651399410bf3d00568ecc92b4aef7267112c5"
      "3ee162ef895d72b57796d8978f6549d62b0935b1d7c7c4ca2b7f5f01a9a512af0e579cef"
      "5befb214af8a6e8989d7c099be4222c55068afd414b1a579b788d34fdc93bdeb2f43c4b9"
      "ef81409feb28918cc14838736f8bd1d663ec6c8b04cbc5a770966c14217c5201d4c20331"
      "71483d546643af447886173fb12c48ac1c9146b3e2eecbdc918288d44cbb12e0f1ac48cf"
      "61e6b2912e5303bcd7570208220459e6c4b30a3dd659e3a7b2219d5e1d15515c08fe348b"
      "4b8feae2d09baee32b6b029212a4fd69be1e7106aa685cdf990ee9bef1f639b183d54705"
      "6ce196f9f4dc0045b5a00880503ef10d1681234a8247e40db01ce8e4feb4f5834704a256"
      "65c3b36118fa0b5ee17ebe3848bac7cab4ac1339b7a6142db0e0445f1968a1b5f692a349"
      "3c8c40bb9cfb4a918916448425abefde587917a9d56155c7946bcbe0b5b945d55508cc8e"
      "426404736816b7d4faa1ad202206d763afe5c9a0592fb20929e916f6637a1c7799ffdfc9"
      "64b7bc21d055ce1dd1e836139065984ce4d5f91efa3d33e0be043390872590d803b4f78d"
      "e5038de77b6c8750a42437255245d999d6ddcab47adcd9a9c21e96344b838a6adf0d1249"
      "5f78386f1990bc298100163d276082f997bef6f91cd5468b1a5e5f6427a7dabeacbdf913"
      "6bf3d943f7c916c0fdffa7cbf8ceb5de2f4416cd6742e7dcaa47ea70965c58d2d547d2ec"
      "640c54147fbd6e602cbf2b65f08aaee344357c655bbd3d5d412ee575317785e75306c560"
      "b6dbe1c3b0c914b5715764f4815d6b9c1da090414bdcb646045cc906c123409177412c02"
      "0a906fafe2b17006c08d81392a10c80dea978dac69cc75f2a0b1692b57498e4e68137f02"
      "100aba475627df4963876049e3b4caa9a02ad60a5007400bfdef91eb5d8d62ec596d73a1"
      "57d5b49cf31839e52867d4c17fa45014bd649974783aaa1edbd8604ec2a1f8f67aff144d"
      "808992d3858736baa6b9d731dea2acbe18ec5da9b1d3d50dcdb953bc8a12ad9dddf6a629"
      "e66a61486038c0baefefa902fa0e3b88e200c82edc665075f247bf81b50348932b4e7a10"
      "31d4166ccb3b9c480a20425c9be869d9dace1eb2484be8a3627e18467c43f51f732cbdc8"
      "f816654e77ed3eb0f5bb7c4bb4c2738bbc645598dccc6bbdb595ca958498f11d12139f06"
      "48de900e15a71e68a86861ba44fa26b9ed7c7a25922a71f896041afe84b99b0ed0fa626e"
      "34ca332ad5c07cdcb2581c2c9863b760cdd475515d1a9b031a231f71a28efaa88e18dca2"
      "f959fbe66ea3ca956e2c835d6e279932e1a16f3d00eac35a2ad9e86cd56721c927799947"
      "b6c5de3445be843cf805a833af1dfa72b776ac76412e0c23cb3003f81ca7babc40e5220d"
      "a894504f2bbdbb298bde76829cc136cfc978945b14011402f04ec743b58f1a696b01940c"
      "fc60f8cd9aa6e49cf61454d380a1fc977a041ef6144e5ddec8e0acbd9e9e566351602636"
      "82c1be1036b59295334043cdb88fd851d90fa6537e384dcb9af2cc04c6c618300705660b"
      "73f4e571248b7b83044b1d8cf6a828ae2dd674bc42c53e5c03556f718dddb9748eb8041e"
      "46e30bcf27b111950aea824751ab3704158ae2741906b8c18c84edc891b6e80c1a034d40"
      "46660deef767669ba14c6c6b4e2bea0180abc8e59287328b4d1e217425159534e5e9f103"
      "9e4987e0b63dc83d96a7ed3519f065d4321c97962f8afc7ce6552823ca36e7c8fed66f8c"
      "40d8d4020eede2c4a885db32750c7b88657e308a88cd4f0d5dd1c5188c816e115ca90f6d"
      "d659141df83aab96333994d18456ae880a7463ceb2e8c506dc665dffa0a8337810075461"
      "ca0efd56734b003c79145afc031c55c4d33169cf6e28403874dcf9ab8c1bac86863d93d6"
      "4311cb6e1a3ca1456845973b452d642c4b47094f0b4251af36c23c3aa24fc4765236753f"
      "a2668931e0e6bd5496039949aeea94661e4ff4f2146f5db927a1932490e421190c1020ef"
      "d8b4051833d409135332c97c29393bec703e37a778b6bc6512fbf95ef2ada4c42bbe6ff6"
      "c69b9016ce49fec63f46db5b7b80c0ae91f190a2c596f0cb9a3511c72c4ff1835c72100d"
      "616b8ea683e73cdc45b76994b4be31c39d4debe45118323662fbd82cf0ac701df285245d"
      "d9f6177489fc13a4e1712dd6f04624b92989c5b34549c4d57521cb7dcb9794aa4e8de502"
      "ab063662cac0c0d54c1911055cb8209735bdd6faeb86f0ecf1a65a3e49431c47cf1260e2"
      "efcf5274e656f06733bfb4fb243ce5ad48834932a9f47458ab02ed516b849d04747ce6fa"
      "32cbbc0cfe94f9f3d94af760049d5c60b999a328e3f200500692c718258086ae7c2015b5"
      "fe7925925cb5784397b0f321cda79255feb9b55fe8ad234f87841832829f98fe8b43721a"
      "6de3a9acb8a4e118a97262b4e623192584123a39a24701be68c7ee0717eca236282e9259"
      "28ea5aa7cb1aec245691da0f7149ce5e2c6b018172dcf5672489e7f880408e477e56a773"
      "da5cd6d2caf5e78d3c03ed5490479b5c123e36a4cbfcd017655b5215f59d504b0a3a0b28"
      "36102e41ca5bf5ed019becdbe323b2c0f3322538bc0dbe8bb54e74b74e900d08cff3e26a"
      "4f03d3bedb27deb72d270007a7c82ecdff314308a10a28794c5550a35be5226c554e8061"
      "4e41df1668ac7b98217c384e3215e6cac5d1b8ef4b600ef974099b8b5a594e03a56866b5"
      "42377c490ea95175327c60669b763cd1164a967c60d1270cb6652781200d26d33750641f"
      "2ea8151108251b0608e2f6112fc6c3bfb5d937e69c8e53e68b154288070e444cf02b4d57"
      "346235987657ee3b782b60a3a665f76d821fdf987b590d7ff079a99621a04d8aff113b05"
      "f1e73805fc0ab40fee96b7b5edc5c4f94646adefed170c9c6f231fc660c670e124b675df"
      "92ea12a0a4b06886cbb7ff554a6da89a4027fba6ef5c4ac45bf36ba974fa30110c75ab3d"
      "38b37698168bcfacbc2b8964746adbe99219852e8c0717d20fdbe4d8400ef608c5c5c22f"
      "a22c02b50a890bac4b063bf86bfd07531f9604c7d15e39c599ff869b937017572500409e"
      "958fda3c1cd7b5755e2dbd37fcd895c28d6d922679f7f32087224568e051b0b7ab1c9ad1"
      "59b55e61660e53c6a065d4061ff443c5980f0df9169ff426d849a69d1b7bf0adcef23d98"
      "674f7325f73521496abd4796559325e37aa720b12cc974dbd1bc6f8ad55475741e0f9d42"
      "af9087cf840b17161cbbda2b815c3757111bbc884554a21eb6827f1289b234e72a53d5d5"
      "acad9488c0ff944a646b40e38eec67ca6df8450b7e978114c7ca97200afc5a11b0a04ab1"
      "9247725a3f421716b3a561cfe31cf2538e6406ef2e0ed395f4dd9387f3c089f806cae388"
      "974cb00ba004a97815a40fba8c114a03e557da5d2536e768432d0ed48ea0523acc434024"
      "c7599c7c822acdbeb1ea8672386b006a0da70c87ed";

  RestrictedData serialized_key = RestrictedData(
      test::HexDecodeOrDie(serialized_key_hex), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(0x03050709));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(), true);

  util::StatusOr<MlDsaParameters> expected_parameters = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlDsaPublicKey> expected_public_key = MlDsaPublicKey::Create(
      *expected_parameters, test::HexDecodeOrDie(public_key_bytes_hex),
      0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<MlDsaPrivateKey> expected_private_key =
      MlDsaPrivateKey::Create(
          *expected_public_key,
          RestrictedData(test::HexDecodeOrDie(private_key_bytes_hex),
                         InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
