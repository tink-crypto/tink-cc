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
///////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/slh_dsa_proto_serialization.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/slhdsa.h"
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
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/signature/slh_dsa_public_key.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/slh_dsa.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::SlhDsaHashType;
using ::google::crypto::tink::SlhDsaKeyFormat;
using ::google::crypto::tink::SlhDsaParams;
using ::google::crypto::tink::SlhDsaSignatureType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.SlhDsaPublicKey";

struct TestCase {
  SlhDsaParameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

class SlhDsaProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  SlhDsaProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(SlhDsaProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    SlhDsaProtoSerializationTestSuite, SlhDsaProtoSerializationTest,
    Values(TestCase{SlhDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{SlhDsaParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{SlhDsaParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw, absl::nullopt, ""}));

TEST_P(SlhDsaProtoSerializationTest,
       ParseSlhDsa128Sha2SmallSignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

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

  const SlhDsaParameters* slh_dsa_parameters =
      dynamic_cast<const SlhDsaParameters*>(parameters->get());
  ASSERT_THAT(slh_dsa_parameters, NotNull());
  EXPECT_THAT(slh_dsa_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(slh_dsa_parameters->GetPrivateKeySizeInBytes(), Eq(64));
  EXPECT_THAT(slh_dsa_parameters->GetSignatureType(),
              Eq(SlhDsaParameters::SignatureType::kSmallSignature));
  EXPECT_THAT(slh_dsa_parameters->GetHashType(),
              Eq(SlhDsaParameters::HashType::kSha2));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse SlhDsaKeyFormat proto")));
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine SlhDsaParameters::HashType")));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaKeyFormat key_format_proto;
  SlhDsaParams& params = *key_format_proto.mutable_params();
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine SlhDsaParameters::Variant")));
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithInvalidSigTypeFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  {
    // Unspecified signature type.
    SlhDsaKeyFormat key_format_proto;
    SlhDsaParams& params = *key_format_proto.mutable_params();
    params.set_sig_type(
        SlhDsaSignatureType::SLH_DSA_SIGNATURE_TYPE_UNSPECIFIED);
    params.set_hash_type(SlhDsaHashType::SHA2);
    params.set_key_size(64);

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(
        parameters.status(),
        StatusIs(
            absl::StatusCode::kInvalidArgument,
            HasSubstr("Could not determine SlhDsaParameters::SignatureType")));
  }
  {
    // Out of range signature type.
    SlhDsaKeyFormat key_format_proto;
    SlhDsaParams& params = *key_format_proto.mutable_params();
    params.set_sig_type(static_cast<SlhDsaSignatureType>(3));
    params.set_hash_type(SlhDsaHashType::SHA2);
    params.set_key_size(64);

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(
        parameters.status(),
        StatusIs(
            absl::StatusCode::kInvalidArgument,
            HasSubstr("Could not determine SlhDsaParameters::SignatureType")));
  }
}

TEST_F(SlhDsaProtoSerializationTest, ParseParametersWithInvalidHashTypeFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  {
    // Unspecified hash type.
    SlhDsaKeyFormat key_format_proto;
    SlhDsaParams& params = *key_format_proto.mutable_params();
    params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
    params.set_hash_type(SlhDsaHashType::SLH_DSA_HASH_TYPE_UNSPECIFIED);
    params.set_key_size(64);

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("Could not determine SlhDsaParameters::HashType")));
  }
  {
    // Out of range hash type.
    SlhDsaKeyFormat key_format_proto;
    SlhDsaParams& params = *key_format_proto.mutable_params();
    params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
    params.set_hash_type(static_cast<SlhDsaHashType>(3));
    params.set_key_size(64);

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);
    EXPECT_THAT(
        parameters.status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("not determine SlhDsaParameters::HashType")));
  }
}

TEST_P(SlhDsaProtoSerializationTest,
       SerializeSlhDsa128Sha2SmallSignatureParametersWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
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

  const internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  SlhDsaKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_TRUE(key_format.has_params());
  EXPECT_THAT(key_format.params().hash_type(), Eq(SlhDsaHashType::SHA2));
  EXPECT_THAT(key_format.params().sig_type(),
              Eq(SlhDsaSignatureType::SMALL_SIGNATURE));
  EXPECT_THAT(key_format.params().key_size(), Eq(64));
}

TEST_P(SlhDsaProtoSerializationTest, ParsePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::SlhDsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, test_case.output_prefix_type,
          test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  absl::StatusOr<SlhDsaParameters> expected_parameters =
      SlhDsaParameters::Create(
          SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
          SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<SlhDsaPublicKey> expected_key =
      SlhDsaPublicKey::Create(*expected_parameters, raw_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(SlhDsaProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse SlhDsaPublicKey proto")));
}

TEST_F(SlhDsaProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  google::crypto::tink::SlhDsaPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(SlhDsaProtoSerializationTest, SerializePublicKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(32);
  absl::StatusOr<SlhDsaPublicKey> key =
      SlhDsaPublicKey::Create(*parameters, raw_key_bytes,
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::SlhDsaPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().key_size(), Eq(64));
  EXPECT_THAT(proto_key.params().hash_type(), Eq(SlhDsaHashType::SHA2));
  EXPECT_THAT(proto_key.params().sig_type(),
              Eq(SlhDsaSignatureType::SMALL_SIGNATURE));
}

TEST_P(SlhDsaProtoSerializationTest, ParsePrivateKeyWorks) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES);

  SLHDSA_SHA2_128S_generate_key(
      reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
      reinterpret_cast<uint8_t*>(&private_key_bytes[0]));

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  google::crypto::tink::SlhDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::SlhDsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, test_case.output_prefix_type,
          test_case.id_requirement);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT((*private_key)->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT((*private_key)->GetParameters().HasIdRequirement(),
              test_case.id_requirement.has_value());

  absl::StatusOr<SlhDsaParameters> expected_parameters =
      SlhDsaParameters::Create(
          SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
          SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<SlhDsaPublicKey> expected_public_key =
      SlhDsaPublicKey::Create(*expected_parameters, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> expected_private_key =
      SlhDsaPrivateKey::Create(
          *expected_public_key,
          RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**private_key, Eq(*expected_private_key));
}

TEST_F(SlhDsaProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse SlhDsaPrivateKey proto")));
}

TEST_F(SlhDsaProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES);

  SLHDSA_SHA2_128S_generate_key(
      reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
      reinterpret_cast<uint8_t*>(&private_key_bytes[0]));

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  google::crypto::tink::SlhDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::SlhDsaPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(SlhDsaProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES);

  SLHDSA_SHA2_128S_generate_key(
      reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
      reinterpret_cast<uint8_t*>(&private_key_bytes[0]));

  SlhDsaParams params;
  params.set_sig_type(SlhDsaSignatureType::SMALL_SIGNATURE);
  params.set_hash_type(SlhDsaHashType::SHA2);
  params.set_key_size(64);

  google::crypto::tink::SlhDsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value(public_key_bytes);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::SlhDsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(private_key_bytes);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(SlhDsaProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES);

  SLHDSA_SHA2_128S_generate_key(
      reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
      reinterpret_cast<uint8_t*>(&private_key_bytes[0]));

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::SlhDsaPrivateKey proto_key;
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
  EXPECT_THAT(proto_key.public_key().params().key_size(), Eq(64));
  EXPECT_THAT(proto_key.public_key().params().hash_type(),
              Eq(SlhDsaHashType::SHA2));
  EXPECT_THAT(proto_key.public_key().params().sig_type(),
              Eq(SlhDsaSignatureType::SMALL_SIGNATURE));
}

TEST_F(SlhDsaProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterSlhDsaProtoSerialization(), IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES);

  SLHDSA_SHA2_128S_generate_key(
      reinterpret_cast<uint8_t*>(&public_key_bytes[0]),
      reinterpret_cast<uint8_t*>(&private_key_bytes[0]));

  absl::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key,
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get()),
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

}  // namespace
}  // namespace tink
}  // namespace crypto
