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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_seed_bytes);

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
          RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_seed_bytes);

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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
  private_key_proto.set_key_value(private_seed_bytes);

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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
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
  EXPECT_THAT(proto_key.key_value(), Eq(private_seed_bytes));
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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
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
  absl::string_view private_seed_bytes =
      raw_private_key.GetPrivateSeedBytes(GetPartialKeyAccess())
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
      RestrictedData(private_seed_bytes, InsecureSecretKeyAccess::Get()),
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
      "0803a396a737975a212d2b5627f836426159eb7a4bd68a3ecf7bc1817a02b1081191a955"
      "c7c682db0571cbc236ae5118b5e17d6702cb1ae3c973a637c940be0d883e99242631d2b5"
      "600466c6d8a037e53e6a6b93335c0efeec0214c39fb03a034492231342a0a4606e6e077f"
      "6ab54073301fb77845aee02ef0bc0dd4279d24b091bc376069c39d66b7c9e0ebaa499219"
      "128a800c1048bd26984771322e648bd1b3ad7adbae647cc7dd4373fc9ab53bdb3e60d394"
      "00f8898b2858bb42772a873bb50a15178b704a001856c8a598f08715e718e0dc2e5fc747"
      "7b4b85763415a70141874b54b1c24340dc8ddd1485e039b970935c614c891f69784397b6"
      "7c9caa2fc70d7f4480a6814634c885c34c9add06cf4321431fb06db586091fbb91b3064d"
      "0f7ccd645b043fd3845830585d11a022b0c22e003a7ce8bb84918153a680be80c08cfaac"
      "9ef92bd87862c67c5252c0a0f4421df4da670e93679934c0cea8aa2271bc0c8154f62579"
      "b0962b865329730b4dea925ea8c09183f743049a193f24667561860b952badd6135578be"
      "df7632fbd32244fcc5db844ef6763a270741273c102f711709f309eec96d3c64637374cc"
      "80bc7b34305adb388fedc58ce15a3a8b2ca0cadb5775316c2c583c053c2cdb98438a8176"
      "8db15c1062bcd3d84e1dea9041228ffbf159771c5d3dacca51e7a15779251f2025a6503d"
      "ccc08c2aab66ed122e8e588d88633febd9c925b2765b0a236718bb343758a1b516a9c521"
      "54b88cf5c398d47a7e8d249c0b3845ce56c6544c658ab44487ec621bfa1d0c5a2d1b775a"
      "c72c22030931428779ff9421d79b9d25c7454b4963eca3b8392882e02121c0b5c32b1b38"
      "7e9010685b94dc29563f5b387a1397c4cac67afa2ce0aa45291220e18bac7da5bb4b3785"
      "8029265ff44165d5946df3553eb52bbc336153645f2c9b76609816decb9e3d1563fb815d"
      "9135767206ad7419ad8719014058c7ff378a59735747756db492ad55a139fda0c5e7301d"
      "cf1b43e438975d5846ff646973e2926fe234ff37c9bfa81e4931c70babc5f285687f9c53"
      "83d422918869e1d8c66b9739c3c24fb8607be67080b39668a8a50fcb08560600a16a5714"
      "7ce0156b96afc3a1558eb28074b03629230e52f5cede6b102ac14d52a6342f3058522c12"
      "07f5bbeab62607b8c8b1d30518c6372c32a7f35671cdf5ada175a0d7b9409d82018ea1c7"
      "13976959ba2241923eb36ca345f85c6ba1028e16b004247a313914a4d12462852f1e250d"
      "f04758fdf368df9083ee2742809b3838272e7d86952d6516db91bf08941e1f4506351012"
      "41f56a96814392a56f1b50ae402c028adaaeac4835876b46dbba9aa2c82d354653d84a0e"
      "95f748b628b9c2d71efb3c38078499773b5c04529976ccb593476ecce32d24d1360b418c"
      "46b242dad07aa32c193c1625a9d11c8afc3b3d0001d21675547517c1c0c2dd773a58b228"
      "eba66ee6068453899eaa81084fc06437a30da15b7a4ecc9357292182ac7b8b7464035bca"
      "37db3ffd421c2f9c9240d40248c6c33eda092c7887b75239cb8723bf32bf0d30b9f0aaaa"
      "6e7394de183d6bf9706550190024921dba03c11989f852b7a9f2b2626167fb1a6e1f948b"
      "d2f5d04d6e342e9dd98b9b4bea6b377bfc0c9d356418bdfc72b7c21f0dfe189d";
  absl::string_view private_seed_bytes_hex =
      "3d617b0f3f78ad7b7ada5f9be9695e632ac62b1f98844792cfa7e5ad91e7456b38bce00b"
      "0a36c62b98940c11b839d43261c014580067209cb267a702135e3b3c";
  absl::string_view serialized_key_hex =
      "1aa7091a02080112a0090803a396a737975a212d2b5627f836426159eb7a4bd68a3ecf7b"
      "c1817a02b1081191a955c7c682db0571cbc236ae5118b5e17d6702cb1ae3c973a637c940"
      "be0d883e99242631d2b5600466c6d8a037e53e6a6b93335c0efeec0214c39fb03a034492"
      "231342a0a4606e6e077f6ab54073301fb77845aee02ef0bc0dd4279d24b091bc376069c3"
      "9d66b7c9e0ebaa499219128a800c1048bd26984771322e648bd1b3ad7adbae647cc7dd43"
      "73fc9ab53bdb3e60d39400f8898b2858bb42772a873bb50a15178b704a001856c8a598f0"
      "8715e718e0dc2e5fc7477b4b85763415a70141874b54b1c24340dc8ddd1485e039b97093"
      "5c614c891f69784397b67c9caa2fc70d7f4480a6814634c885c34c9add06cf4321431fb0"
      "6db586091fbb91b3064d0f7ccd645b043fd3845830585d11a022b0c22e003a7ce8bb8491"
      "8153a680be80c08cfaac9ef92bd87862c67c5252c0a0f4421df4da670e93679934c0cea8"
      "aa2271bc0c8154f62579b0962b865329730b4dea925ea8c09183f743049a193f24667561"
      "860b952badd6135578bedf7632fbd32244fcc5db844ef6763a270741273c102f711709f3"
      "09eec96d3c64637374cc80bc7b34305adb388fedc58ce15a3a8b2ca0cadb5775316c2c58"
      "3c053c2cdb98438a81768db15c1062bcd3d84e1dea9041228ffbf159771c5d3dacca51e7"
      "a15779251f2025a6503dccc08c2aab66ed122e8e588d88633febd9c925b2765b0a236718"
      "bb343758a1b516a9c52154b88cf5c398d47a7e8d249c0b3845ce56c6544c658ab44487ec"
      "621bfa1d0c5a2d1b775ac72c22030931428779ff9421d79b9d25c7454b4963eca3b83928"
      "82e02121c0b5c32b1b387e9010685b94dc29563f5b387a1397c4cac67afa2ce0aa452912"
      "20e18bac7da5bb4b37858029265ff44165d5946df3553eb52bbc336153645f2c9b766098"
      "16decb9e3d1563fb815d9135767206ad7419ad8719014058c7ff378a59735747756db492"
      "ad55a139fda0c5e7301dcf1b43e438975d5846ff646973e2926fe234ff37c9bfa81e4931"
      "c70babc5f285687f9c5383d422918869e1d8c66b9739c3c24fb8607be67080b39668a8a5"
      "0fcb08560600a16a57147ce0156b96afc3a1558eb28074b03629230e52f5cede6b102ac1"
      "4d52a6342f3058522c1207f5bbeab62607b8c8b1d30518c6372c32a7f35671cdf5ada175"
      "a0d7b9409d82018ea1c713976959ba2241923eb36ca345f85c6ba1028e16b004247a3139"
      "14a4d12462852f1e250df04758fdf368df9083ee2742809b3838272e7d86952d6516db91"
      "bf08941e1f450635101241f56a96814392a56f1b50ae402c028adaaeac4835876b46dbba"
      "9aa2c82d354653d84a0e95f748b628b9c2d71efb3c38078499773b5c04529976ccb59347"
      "6ecce32d24d1360b418c46b242dad07aa32c193c1625a9d11c8afc3b3d0001d216755475"
      "17c1c0c2dd773a58b228eba66ee6068453899eaa81084fc06437a30da15b7a4ecc935729"
      "2182ac7b8b7464035bca37db3ffd421c2f9c9240d40248c6c33eda092c7887b75239cb87"
      "23bf32bf0d30b9f0aaaa6e7394de183d6bf9706550190024921dba03c11989f852b7a9f2"
      "b2626167fb1a6e1f948bd2f5d04d6e342e9dd98b9b4bea6b377bfc0c9d356418bdfc72b7"
      "c21f0dfe189d12403d617b0f3f78ad7b7ada5f9be9695e632ac62b1f98844792cfa7e5ad"
      "91e7456b38bce00b0a36c62b98940c11b839d43261c014580067209cb267a702135e3b3"
      "c";

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
          RestrictedData(test::HexDecodeOrDie(private_seed_bytes_hex),
                         InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
