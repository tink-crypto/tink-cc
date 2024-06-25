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

#include "tink/experimental/pqcrypto/kem/ml_kem_proto_serialization.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/internal/ml_kem_test_util.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/experimental/pqcrypto/ml_kem.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::MlKemKeyFormat;
using ::google::crypto::tink::MlKemKeySize;
using ::google::crypto::tink::MlKemParams;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPublicKey";

class MlKemProtoSerializationTest : public ::testing::Test {
 protected:
  MlKemProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

MlKemPrivateKey GenerateMlKem768PrivateKey(int id_requirement) {
  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  CHECK_OK(parameters);

  util::StatusOr<MlKemPrivateKey> private_key =
      internal::GenerateMlKemPrivateKey(*parameters, id_requirement);
  CHECK_OK(private_key);

  return *private_key;
}

TEST_F(MlKemProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());
}

TEST_F(MlKemProtoSerializationTest, ParseMlKem768ParametersWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  MlKemKeyFormat key_format_proto;
  MlKemParams& params = *key_format_proto.mutable_params();
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_EQ((*parameters)->HasIdRequirement(), true);

  const MlKemParameters* ml_kem_parameters =
      dynamic_cast<const MlKemParameters*>(parameters->get());
  ASSERT_THAT(ml_kem_parameters, NotNull());
  EXPECT_THAT(ml_kem_parameters->GetVariant(),
              Eq(MlKemParameters::Variant::kTink));
  EXPECT_THAT(ml_kem_parameters->GetKeySize(), Eq(768));
}

TEST_F(MlKemProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlKemKeyFormat proto")));
}

TEST_F(MlKemProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  MlKemKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  MlKemParams& params = *key_format_proto.mutable_params();
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(MlKemProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  MlKemKeyFormat key_format_proto;
  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MlKemKeyFormat proto is missing params")));
}

TEST_F(MlKemProtoSerializationTest,
       ParseParametersWithInvalidOutputPrefixFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  MlKemKeyFormat key_format_proto;
  MlKemParams& params = *key_format_proto.mutable_params();
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

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
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Invalid output prefix type RAW for MlKemParameters")));
}

TEST_F(MlKemProtoSerializationTest,
       ParseParametersWithUnknownOutputPrefixFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  MlKemKeyFormat key_format_proto;
  MlKemParams& params = *key_format_proto.mutable_params();
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

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
               HasSubstr("Could not determine MlKemParameters::Variant")));
}

TEST_F(MlKemProtoSerializationTest, SerializeMlKem768ParametersWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
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
              Eq(OutputPrefixType::TINK));

  MlKemKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().ml_kem_key_size(),
              Eq(MlKemKeySize::ML_KEM_768));
}

TEST_F(MlKemProtoSerializationTest, RoundTripMlKem768Parameters) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
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

TEST_F(MlKemProtoSerializationTest, ParsePublicKeyWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlKemParams params;
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  google::crypto::tink::MlKemPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(0x03050709));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(), true);

  util::StatusOr<MlKemParameters> expected_parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlKemPublicKey> expected_key = MlKemPublicKey::Create(
      *expected_parameters, raw_key_bytes, 0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(MlKemProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PUBLIC,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlKemPublicKey proto")));
}

TEST_F(MlKemProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlKemParams params;
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  google::crypto::tink::MlKemPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key, KeyData::ASYMMETRIC_PUBLIC,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(MlKemProtoSerializationTest, SerializePublicKeyWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlKemPublicKey> key = MlKemPublicKey::Create(
      *parameters, raw_key_bytes, 0x03050709, GetPartialKeyAccess());
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
              Eq(OutputPrefixType::TINK));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(0x03050709));

  google::crypto::tink::MlKemPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ml_kem_key_size(),
              Eq(MlKemKeySize::ML_KEM_768));
}

TEST_F(MlKemProtoSerializationTest, RoundTripPublicKey) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view raw_key_bytes =
      private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlKemPublicKey> key = MlKemPublicKey::Create(
      *parameters, raw_key_bytes, 0x03050709, GetPartialKeyAccess());
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

TEST_F(MlKemProtoSerializationTest, ParsePrivateKeyWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid private key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlKemParams params;
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  google::crypto::tink::MlKemPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlKemPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

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

  util::StatusOr<MlKemParameters> expected_parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlKemPublicKey> expected_public_key =
      MlKemPublicKey::Create(*expected_parameters, public_key_bytes, 0x03050709,
                             GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<MlKemPrivateKey> expected_private_key =
      MlKemPrivateKey::Create(
          *expected_public_key,
          RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

TEST_F(MlKemProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                              KeyData::ASYMMETRIC_PRIVATE,
                                              OutputPrefixType::TINK,
                                              /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse MlKemPrivateKey proto")));
}

TEST_F(MlKemProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlKemParams params;
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  google::crypto::tink::MlKemPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlKemPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(MlKemProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  MlKemParams params;
  params.set_ml_kem_key_size(MlKemKeySize::ML_KEM_768);

  google::crypto::tink::MlKemPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::MlKemPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key, KeyData::ASYMMETRIC_PRIVATE,
          OutputPrefixType::TINK, 0x03050709);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_F(MlKemProtoSerializationTest, SerializePrivateKey) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *parameters, public_key_bytes, 0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
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
              Eq(OutputPrefixType::TINK));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(0x03050709));

  google::crypto::tink::MlKemPrivateKey proto_key;
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
  EXPECT_THAT(proto_key.public_key().params().ml_kem_key_size(),
              Eq(MlKemKeySize::ML_KEM_768));
}

TEST_F(MlKemProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlKemPublicKey> public_key =
      MlKemPublicKey::Create(*parameters, public_key_bytes,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
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

TEST_F(MlKemProtoSerializationTest, RoundTripPrivateKey) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  // Generate valid public key bytes.
  MlKemPrivateKey raw_private_key = GenerateMlKem768PrivateKey(0x03050709);
  absl::string_view private_key_bytes =
      raw_private_key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get());
  absl::string_view public_key_bytes =
      raw_private_key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());

  util::StatusOr<MlKemParameters> parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *parameters, public_key_bytes, 0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<MlKemPrivateKey> private_key = MlKemPrivateKey::Create(
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

TEST_F(MlKemProtoSerializationTest, ParseGoldenPrivateKeyWorks) {
  ASSERT_THAT(RegisterMlKemProtoSerialization(), IsOk());

  absl::string_view public_key_bytes_hex =
      "156a4b91f8823e9a6f6103797692494f5007d6e49a032999f4a33d64c4abab32595a067c"
      "0951296254a8cc90849f76156d451b25b4b1b172b2fe470ddd419b3fd998154c3dc34a64"
      "77136651dc32b78723c869ae09e19632d9b04a580b85dc5810aac1e31c38302a01cab46b"
      "0b980d97b6506fa91a7845045f07b001c427af6226e220192460adcd64822bf24f145990"
      "6278c791896cfc562101a603ef627b46a3bcde28573c9322640ab4cceb484da756585705"
      "7b6261519b8952941513b749b9e868742531079ca5bf5463ff85936d112ed8b32e28987c"
      "efa76d00dbb0a3679daef258669b82ee8040faab0e29908e8f5602cd9a4c957a32d777ba"
      "354152f1f18f18c3b44c9a1f95cb9b252cb1aed06003a504da694d0790095b712bc4944b"
      "fe054da92c0b1bd57acbba9ccaa136b7eb040f4a0c6cb1311c081be1a65089c1cf3abb85"
      "e9491efbc88b24819090309c4ee57ffb86b2ef0c1dfad671e1476ce71caf34ba873ed3a6"
      "85c02a1cd083e92c1afa2682d1e4b88c7981974266c491901fd51123e44c106b6aa5ba35"
      "64183feccbbc771c2564400fc54819e811b690c48195e7919a633d60f61e6e3a1e814776"
      "85aacb1e20a0f7c1604e963634c33428c719dac0596f4cbb69b60065e548c0563e819a7b"
      "438172e782103262c613ac0a83c4b0412691d90a1283fb950e1599074788544abc1a0416"
      "33dc97f2ac805da58d2d49ab968b0f0bbb6e08ca3713c50b02c80f14219263a57efda092"
      "41ea8352320af8371fa7fc619287554ee988f9c8a6d3939245b4a57bac441e59b27d96be"
      "d4785387593a9c23c27cf8b39346bc584ccf1be2c679275f820030e06472ef4c6ff247ad"
      "46300a2f47a457bb1785b7889646b13ea844d350ac242663d5900ea87b77ba6130195347"
      "1d5a345b14abdf482235128c9057a16adc50f8d726c86c6e61c77f54b44bcfba54cc72c2"
      "39c9405166c75a05803ca18713e26d97372d9f258548b3b2304927b3b3b63fc17f620a0f"
      "f5ca928a2695e1f9c0f154512d2c8250a7cbfbaabd9554628eb9abd1123c5392246668b7"
      "b57b121274b51bd34d8cc28a3a03bf006c1ac3016fb156cd5283702ce8bcf5eb35f851b4"
      "d11a30d5020821e78a5ac00bcd0c627c31533639665e260fd1b39141d34b26e31dedcca9"
      "1d2a99c9d504b762970a259be2490063e554fcb1b7fc374d76f4ab3adb2462209f55f06f"
      "ede64de9b70ec0640e1f5c499dba12cb9280ca1cc405361887787889c009e18cc384318c"
      "d8774d49e0a08a375347034effe77820c40f7dd7a878871be273257f6576ff295f91ab83"
      "a0bb8f0db94a00d35611bac243346dadfbbb83a340585a7d374c0cd2a27640456a075179"
      "0cf4b4b5ea6662fbc2c87b2c8e671df64a997c4994f3294b75a54fc360c9df53596a153a"
      "6981576dec3d192a31a19c03ff68a30b0041418a23f894adf5418a1df717148c649665c0"
      "3d77157bdbb034c5bc6b1cab60faace0c1bc570436cc4732777bcc04a05374585d76e193"
      "27d66e30fa2d71851f9e415656c97ce2a1175315383e549fa60708f46a9bde81ae3d8b81"
      "90b38314c799fcb21656b97ec9716fba7783b9da2fd5256f64c79185a5397f5b831dea0c"
      "bb2fcce47bf190d8a11f7b506f49c4d5f26608949ebad06cc8334044d503479d";
  absl::string_view private_key_bytes_hex =
      "1aa6ab82768d4ba8a125bb65bc01badf84a12eb19b3a48602d44b0a972463188c949eacc"
      "8e691b8f70a24f594d26e81cd0f061a048420237a63d2c10ccf4b7c5ba159b953768826b"
      "4e75bbd9c1091c92ad57d5032787c8a1180303735b9506935f9323d639c930a4c94db542"
      "bd33417519855fe6aee9671dbe3c0f68920ecbf51595d8be60cab06d5641a69623024833"
      "300365f4246e18ac0ab30035cfd376c8c67d9bf4478f4239ac0840262a773ba343bc3020"
      "dd949a21dc976416042c874434505f0ea2090ddc03b847a57bd5c257d72d1e085f7a4064"
      "52d7b0d10015d1470a9ee0c3ce84455e365c6bcc78bae1120358a5c72761846cbb8b3227"
      "f5004bdb04a2b5bc2bdf821ab26669ee89324008221c9cb3b419961a7068999a9064a734"
      "02245e4d79640f4c664c290e4d2193d1057a9ff66e0732acf318cddf354f70ba2f3acac9"
      "83ea93d483319e44898f83110ff55db1a15dc93b398b1c7d45f0270ea834c0f35096805e"
      "2af409652ba0c13156cb6743bb996b41b995c56ac483602977b44e920a54fdfb99c8b370"
      "b942183a5b282d990a5eeaa6b7811e61c093fc08467681b7769799828ca2c3a694a73a7a"
      "69aca9aba1a942a914f9f73c6079c8aae0890b8b53e12b2031994ed0c683ff8370e30419"
      "03486684297cd01440931a805e07b2dadaae26c4a8ba97b1f3471c0dd35f9e5596bcd119"
      "85a2ac65b5205f800516968446d151dda984411baee4a97ed7168913616a5e3165068ca1"
      "70eb07536a51eb4b24d682786580171eea2c98893a23d37d11676e132b08f9ab04343989"
      "c0ecc045616cdd32a8f26cace0c382b3ea57ce35bf301622424b72fec1150bd2cb4a2344"
      "1910720142cafad983f8b6ca23e97090967380410a14357becbb7590366b79c95baab98a"
      "49069200a55a74acbeb0117971e2cec91a2c7c547df00045e0e112dfda0deeba061759ba"
      "e8535459c355aa378be4bb0098e6ae02d82f4caab35be4ad996a4d96399b15b18c6441ba"
      "e0571dc32955dbaac990bb5a67f41bc308745a9497442b6eb1ea6300b25f10a59f849686"
      "35e1bd35892dd569182bd961d142021f669da44abca4c75e7e53c51ac6b50219c7e1cb69"
      "7a674c9df5a8120379ee3c0e2d96baf481a8684861fd46c14b782b20110122274590d398"
      "2da1bc06614f3c3c4453b1342a143aec8a4281f55164e40cdc886325cb71cd75cfa1b582"
      "89683f8b580365489b386c119a71843fda3d02b82d41fb869971469179cb41468748aa69"
      "55134d2ca1381b0145a383af9c6479f79b0f6d76b95184afee789696ac3e0a3cc5b9f51c"
      "1c6244aec965a11cb7bd42cd4e98ab874b96c375a853ab0281a19105a71ac431662812b1"
      "a8770331f03da60a71e9763dfe910420dc7aa1d96320a3173af498392bac13025d9946b6"
      "03f25d955243c0f1479d48b62c67c853dbb6bb96b397b7cb75982af90434e2d3bce4fa40"
      "ab4506527294794786d5712f453c34c875261df12dc28a1fd9a4c28fe79031792ccde6c0"
      "04cba414d10119b78135f86d84c9bbcde46ac2ec723682c8eec6ae28b5475770665208a6"
      "89f88a4c29494ef1a023821a8d727ac6b7c090a9338fbc7a8bd92e66ca0f7f77393937ac"
      "156a4b91f8823e9a6f6103797692494f5007d6e49a032999f4a33d64c4abab32595a067c"
      "0951296254a8cc90849f76156d451b25b4b1b172b2fe470ddd419b3fd998154c3dc34a64"
      "77136651dc32b78723c869ae09e19632d9b04a580b85dc5810aac1e31c38302a01cab46b"
      "0b980d97b6506fa91a7845045f07b001c427af6226e220192460adcd64822bf24f145990"
      "6278c791896cfc562101a603ef627b46a3bcde28573c9322640ab4cceb484da756585705"
      "7b6261519b8952941513b749b9e868742531079ca5bf5463ff85936d112ed8b32e28987c"
      "efa76d00dbb0a3679daef258669b82ee8040faab0e29908e8f5602cd9a4c957a32d777ba"
      "354152f1f18f18c3b44c9a1f95cb9b252cb1aed06003a504da694d0790095b712bc4944b"
      "fe054da92c0b1bd57acbba9ccaa136b7eb040f4a0c6cb1311c081be1a65089c1cf3abb85"
      "e9491efbc88b24819090309c4ee57ffb86b2ef0c1dfad671e1476ce71caf34ba873ed3a6"
      "85c02a1cd083e92c1afa2682d1e4b88c7981974266c491901fd51123e44c106b6aa5ba35"
      "64183feccbbc771c2564400fc54819e811b690c48195e7919a633d60f61e6e3a1e814776"
      "85aacb1e20a0f7c1604e963634c33428c719dac0596f4cbb69b60065e548c0563e819a7b"
      "438172e782103262c613ac0a83c4b0412691d90a1283fb950e1599074788544abc1a0416"
      "33dc97f2ac805da58d2d49ab968b0f0bbb6e08ca3713c50b02c80f14219263a57efda092"
      "41ea8352320af8371fa7fc619287554ee988f9c8a6d3939245b4a57bac441e59b27d96be"
      "d4785387593a9c23c27cf8b39346bc584ccf1be2c679275f820030e06472ef4c6ff247ad"
      "46300a2f47a457bb1785b7889646b13ea844d350ac242663d5900ea87b77ba6130195347"
      "1d5a345b14abdf482235128c9057a16adc50f8d726c86c6e61c77f54b44bcfba54cc72c2"
      "39c9405166c75a05803ca18713e26d97372d9f258548b3b2304927b3b3b63fc17f620a0f"
      "f5ca928a2695e1f9c0f154512d2c8250a7cbfbaabd9554628eb9abd1123c5392246668b7"
      "b57b121274b51bd34d8cc28a3a03bf006c1ac3016fb156cd5283702ce8bcf5eb35f851b4"
      "d11a30d5020821e78a5ac00bcd0c627c31533639665e260fd1b39141d34b26e31dedcca9"
      "1d2a99c9d504b762970a259be2490063e554fcb1b7fc374d76f4ab3adb2462209f55f06f"
      "ede64de9b70ec0640e1f5c499dba12cb9280ca1cc405361887787889c009e18cc384318c"
      "d8774d49e0a08a375347034effe77820c40f7dd7a878871be273257f6576ff295f91ab83"
      "a0bb8f0db94a00d35611bac243346dadfbbb83a340585a7d374c0cd2a27640456a075179"
      "0cf4b4b5ea6662fbc2c87b2c8e671df64a997c4994f3294b75a54fc360c9df53596a153a"
      "6981576dec3d192a31a19c03ff68a30b0041418a23f894adf5418a1df717148c649665c0"
      "3d77157bdbb034c5bc6b1cab60faace0c1bc570436cc4732777bcc04a05374585d76e193"
      "27d66e30fa2d71851f9e415656c97ce2a1175315383e549fa60708f46a9bde81ae3d8b81"
      "90b38314c799fcb21656b97ec9716fba7783b9da2fd5256f64c79185a5397f5b831dea0c"
      "bb2fcce47bf190d8a11f7b506f49c4d5f26608949ebad06cc8334044d503479dd93605f4"
      "d9bd9bfc29bfcff7113dfe2871bbe03c80c76fc715d12c9989fc5c10d9cdff3ba2ba12f0"
      "c5d75eff00a86e18667e00228027f96bddffa4072db8415a";
  absl::string_view serialized_key_hex =
      "1aa7091a02080112a009156a4b91f8823e9a6f6103797692494f5007d6e49a032999f4a3"
      "3d64c4abab32595a067c0951296254a8cc90849f76156d451b25b4b1b172b2fe470ddd41"
      "9b3fd998154c3dc34a6477136651dc32b78723c869ae09e19632d9b04a580b85dc5810aa"
      "c1e31c38302a01cab46b0b980d97b6506fa91a7845045f07b001c427af6226e220192460"
      "adcd64822bf24f1459906278c791896cfc562101a603ef627b46a3bcde28573c9322640a"
      "b4cceb484da7565857057b6261519b8952941513b749b9e868742531079ca5bf5463ff85"
      "936d112ed8b32e28987cefa76d00dbb0a3679daef258669b82ee8040faab0e29908e8f56"
      "02cd9a4c957a32d777ba354152f1f18f18c3b44c9a1f95cb9b252cb1aed06003a504da69"
      "4d0790095b712bc4944bfe054da92c0b1bd57acbba9ccaa136b7eb040f4a0c6cb1311c08"
      "1be1a65089c1cf3abb85e9491efbc88b24819090309c4ee57ffb86b2ef0c1dfad671e147"
      "6ce71caf34ba873ed3a685c02a1cd083e92c1afa2682d1e4b88c7981974266c491901fd5"
      "1123e44c106b6aa5ba3564183feccbbc771c2564400fc54819e811b690c48195e7919a63"
      "3d60f61e6e3a1e81477685aacb1e20a0f7c1604e963634c33428c719dac0596f4cbb69b6"
      "0065e548c0563e819a7b438172e782103262c613ac0a83c4b0412691d90a1283fb950e15"
      "99074788544abc1a041633dc97f2ac805da58d2d49ab968b0f0bbb6e08ca3713c50b02c8"
      "0f14219263a57efda09241ea8352320af8371fa7fc619287554ee988f9c8a6d3939245b4"
      "a57bac441e59b27d96bed4785387593a9c23c27cf8b39346bc584ccf1be2c679275f8200"
      "30e06472ef4c6ff247ad46300a2f47a457bb1785b7889646b13ea844d350ac242663d590"
      "0ea87b77ba61301953471d5a345b14abdf482235128c9057a16adc50f8d726c86c6e61c7"
      "7f54b44bcfba54cc72c239c9405166c75a05803ca18713e26d97372d9f258548b3b23049"
      "27b3b3b63fc17f620a0ff5ca928a2695e1f9c0f154512d2c8250a7cbfbaabd9554628eb9"
      "abd1123c5392246668b7b57b121274b51bd34d8cc28a3a03bf006c1ac3016fb156cd5283"
      "702ce8bcf5eb35f851b4d11a30d5020821e78a5ac00bcd0c627c31533639665e260fd1b3"
      "9141d34b26e31dedcca91d2a99c9d504b762970a259be2490063e554fcb1b7fc374d76f4"
      "ab3adb2462209f55f06fede64de9b70ec0640e1f5c499dba12cb9280ca1cc40536188778"
      "7889c009e18cc384318cd8774d49e0a08a375347034effe77820c40f7dd7a878871be273"
      "257f6576ff295f91ab83a0bb8f0db94a00d35611bac243346dadfbbb83a340585a7d374c"
      "0cd2a27640456a0751790cf4b4b5ea6662fbc2c87b2c8e671df64a997c4994f3294b75a5"
      "4fc360c9df53596a153a6981576dec3d192a31a19c03ff68a30b0041418a23f894adf541"
      "8a1df717148c649665c03d77157bdbb034c5bc6b1cab60faace0c1bc570436cc4732777b"
      "cc04a05374585d76e19327d66e30fa2d71851f9e415656c97ce2a1175315383e549fa607"
      "08f46a9bde81ae3d8b8190b38314c799fcb21656b97ec9716fba7783b9da2fd5256f64c7"
      "9185a5397f5b831dea0cbb2fcce47bf190d8a11f7b506f49c4d5f26608949ebad06cc833"
      "4044d503479d12e0121aa6ab82768d4ba8a125bb65bc01badf84a12eb19b3a48602d44b0"
      "a972463188c949eacc8e691b8f70a24f594d26e81cd0f061a048420237a63d2c10ccf4b7"
      "c5ba159b953768826b4e75bbd9c1091c92ad57d5032787c8a1180303735b9506935f9323"
      "d639c930a4c94db542bd33417519855fe6aee9671dbe3c0f68920ecbf51595d8be60cab0"
      "6d5641a69623024833300365f4246e18ac0ab30035cfd376c8c67d9bf4478f4239ac0840"
      "262a773ba343bc3020dd949a21dc976416042c874434505f0ea2090ddc03b847a57bd5c2"
      "57d72d1e085f7a406452d7b0d10015d1470a9ee0c3ce84455e365c6bcc78bae1120358a5"
      "c72761846cbb8b3227f5004bdb04a2b5bc2bdf821ab26669ee89324008221c9cb3b41996"
      "1a7068999a9064a73402245e4d79640f4c664c290e4d2193d1057a9ff66e0732acf318cd"
      "df354f70ba2f3acac983ea93d483319e44898f83110ff55db1a15dc93b398b1c7d45f027"
      "0ea834c0f35096805e2af409652ba0c13156cb6743bb996b41b995c56ac483602977b44e"
      "920a54fdfb99c8b370b942183a5b282d990a5eeaa6b7811e61c093fc08467681b7769799"
      "828ca2c3a694a73a7a69aca9aba1a942a914f9f73c6079c8aae0890b8b53e12b2031994e"
      "d0c683ff8370e3041903486684297cd01440931a805e07b2dadaae26c4a8ba97b1f3471c"
      "0dd35f9e5596bcd11985a2ac65b5205f800516968446d151dda984411baee4a97ed71689"
      "13616a5e3165068ca170eb07536a51eb4b24d682786580171eea2c98893a23d37d11676e"
      "132b08f9ab04343989c0ecc045616cdd32a8f26cace0c382b3ea57ce35bf301622424b72"
      "fec1150bd2cb4a23441910720142cafad983f8b6ca23e97090967380410a14357becbb75"
      "90366b79c95baab98a49069200a55a74acbeb0117971e2cec91a2c7c547df00045e0e112"
      "dfda0deeba061759bae8535459c355aa378be4bb0098e6ae02d82f4caab35be4ad996a4d"
      "96399b15b18c6441bae0571dc32955dbaac990bb5a67f41bc308745a9497442b6eb1ea63"
      "00b25f10a59f84968635e1bd35892dd569182bd961d142021f669da44abca4c75e7e53c5"
      "1ac6b50219c7e1cb697a674c9df5a8120379ee3c0e2d96baf481a8684861fd46c14b782b"
      "20110122274590d3982da1bc06614f3c3c4453b1342a143aec8a4281f55164e40cdc8863"
      "25cb71cd75cfa1b58289683f8b580365489b386c119a71843fda3d02b82d41fb86997146"
      "9179cb41468748aa6955134d2ca1381b0145a383af9c6479f79b0f6d76b95184afee7896"
      "96ac3e0a3cc5b9f51c1c6244aec965a11cb7bd42cd4e98ab874b96c375a853ab0281a191"
      "05a71ac431662812b1a8770331f03da60a71e9763dfe910420dc7aa1d96320a3173af498"
      "392bac13025d9946b603f25d955243c0f1479d48b62c67c853dbb6bb96b397b7cb75982a"
      "f90434e2d3bce4fa40ab4506527294794786d5712f453c34c875261df12dc28a1fd9a4c2"
      "8fe79031792ccde6c004cba414d10119b78135f86d84c9bbcde46ac2ec723682c8eec6ae"
      "28b5475770665208a689f88a4c29494ef1a023821a8d727ac6b7c090a9338fbc7a8bd92e"
      "66ca0f7f77393937ac156a4b91f8823e9a6f6103797692494f5007d6e49a032999f4a33d"
      "64c4abab32595a067c0951296254a8cc90849f76156d451b25b4b1b172b2fe470ddd419b"
      "3fd998154c3dc34a6477136651dc32b78723c869ae09e19632d9b04a580b85dc5810aac1"
      "e31c38302a01cab46b0b980d97b6506fa91a7845045f07b001c427af6226e220192460ad"
      "cd64822bf24f1459906278c791896cfc562101a603ef627b46a3bcde28573c9322640ab4"
      "cceb484da7565857057b6261519b8952941513b749b9e868742531079ca5bf5463ff8593"
      "6d112ed8b32e28987cefa76d00dbb0a3679daef258669b82ee8040faab0e29908e8f5602"
      "cd9a4c957a32d777ba354152f1f18f18c3b44c9a1f95cb9b252cb1aed06003a504da694d"
      "0790095b712bc4944bfe054da92c0b1bd57acbba9ccaa136b7eb040f4a0c6cb1311c081b"
      "e1a65089c1cf3abb85e9491efbc88b24819090309c4ee57ffb86b2ef0c1dfad671e1476c"
      "e71caf34ba873ed3a685c02a1cd083e92c1afa2682d1e4b88c7981974266c491901fd511"
      "23e44c106b6aa5ba3564183feccbbc771c2564400fc54819e811b690c48195e7919a633d"
      "60f61e6e3a1e81477685aacb1e20a0f7c1604e963634c33428c719dac0596f4cbb69b600"
      "65e548c0563e819a7b438172e782103262c613ac0a83c4b0412691d90a1283fb950e1599"
      "074788544abc1a041633dc97f2ac805da58d2d49ab968b0f0bbb6e08ca3713c50b02c80f"
      "14219263a57efda09241ea8352320af8371fa7fc619287554ee988f9c8a6d3939245b4a5"
      "7bac441e59b27d96bed4785387593a9c23c27cf8b39346bc584ccf1be2c679275f820030"
      "e06472ef4c6ff247ad46300a2f47a457bb1785b7889646b13ea844d350ac242663d5900e"
      "a87b77ba61301953471d5a345b14abdf482235128c9057a16adc50f8d726c86c6e61c77f"
      "54b44bcfba54cc72c239c9405166c75a05803ca18713e26d97372d9f258548b3b2304927"
      "b3b3b63fc17f620a0ff5ca928a2695e1f9c0f154512d2c8250a7cbfbaabd9554628eb9ab"
      "d1123c5392246668b7b57b121274b51bd34d8cc28a3a03bf006c1ac3016fb156cd528370"
      "2ce8bcf5eb35f851b4d11a30d5020821e78a5ac00bcd0c627c31533639665e260fd1b391"
      "41d34b26e31dedcca91d2a99c9d504b762970a259be2490063e554fcb1b7fc374d76f4ab"
      "3adb2462209f55f06fede64de9b70ec0640e1f5c499dba12cb9280ca1cc4053618877878"
      "89c009e18cc384318cd8774d49e0a08a375347034effe77820c40f7dd7a878871be27325"
      "7f6576ff295f91ab83a0bb8f0db94a00d35611bac243346dadfbbb83a340585a7d374c0c"
      "d2a27640456a0751790cf4b4b5ea6662fbc2c87b2c8e671df64a997c4994f3294b75a54f"
      "c360c9df53596a153a6981576dec3d192a31a19c03ff68a30b0041418a23f894adf5418a"
      "1df717148c649665c03d77157bdbb034c5bc6b1cab60faace0c1bc570436cc4732777bcc"
      "04a05374585d76e19327d66e30fa2d71851f9e415656c97ce2a1175315383e549fa60708"
      "f46a9bde81ae3d8b8190b38314c799fcb21656b97ec9716fba7783b9da2fd5256f64c791"
      "85a5397f5b831dea0cbb2fcce47bf190d8a11f7b506f49c4d5f26608949ebad06cc83340"
      "44d503479dd93605f4d9bd9bfc29bfcff7113dfe2871bbe03c80c76fc715d12c9989fc5c"
      "10d9cdff3ba2ba12f0c5d75eff00a86e18667e00228027f96bddffa4072db8415a";

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

  util::StatusOr<MlKemParameters> expected_parameters = MlKemParameters::Create(
      /*key_size=*/768, MlKemParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<MlKemPublicKey> expected_public_key = MlKemPublicKey::Create(
      *expected_parameters, test::HexDecodeOrDie(public_key_bytes_hex),
      0x03050709, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  util::StatusOr<MlKemPrivateKey> expected_private_key =
      MlKemPrivateKey::Create(
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
