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

#include "tink/aead/x_aes_gcm_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/aead/x_aes_gcm_parameters.h"
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
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/x_aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::InsecureSecretKeyAccess;
using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::MutableSerializationRegistry;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::internal::ProtoKeySerialization;
using ::crypto::tink::internal::ProtoParametersSerialization;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::XAesGcmKeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct XAesGcmTestCase {
  XAesGcmParameters::Variant variant;
  int salt_size;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
};

constexpr int kKeySize = 32;
constexpr int kSaltSize = 12;
constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.XAesGcmKey";

class XAesGcmProtoSerializationTest : public TestWithParam<XAesGcmTestCase> {
 protected:
  void SetUp() override {
    MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(XAesGcmProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    XAesGcmProtoSerializationTestSuite, XAesGcmProtoSerializationTest,
    Values(XAesGcmTestCase{XAesGcmParameters::Variant::kNoPrefix, kSaltSize,
                           OutputPrefixTypeEnum::kRaw,
                           /*id=*/absl::nullopt, /*output_prefix=*/""},
           XAesGcmTestCase{
               XAesGcmParameters::Variant::kTink, kSaltSize,
               OutputPrefixTypeEnum::kTink,
               /*id=*/0x02030400,
               /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)}));

XAesGcmKeyFormat ValidKeyFormat(int salt_size) {
  XAesGcmKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.mutable_params()->set_salt_size(salt_size);
  return key_format_proto;
}

TEST_P(XAesGcmProtoSerializationTest, ParseParameters) {
  XAesGcmTestCase test_case = GetParam();
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          ValidKeyFormat(test_case.salt_size).SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const XAesGcmParameters* gcm_params =
      dynamic_cast<const XAesGcmParameters*>(params->get());
  ASSERT_THAT(gcm_params, NotNull());
  EXPECT_THAT(gcm_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(gcm_params->SaltSizeBytes(), Eq(test_case.salt_size));
}

TEST_F(XAesGcmProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeEnum::kRaw,
                                           "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse XAesGcmKeyFormat proto")));
}

TEST_F(XAesGcmProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          ValidKeyFormat(kSaltSize).SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine XAesGcmParameters::Variant")));
}

TEST_F(XAesGcmProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
  XAesGcmKeyFormat key_format_proto = ValidKeyFormat(kSaltSize);
  key_format_proto.set_version(1);
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(XAesGcmProtoSerializationTest, SerializeParameters) {
  const XAesGcmTestCase& test_case = GetParam();
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  absl::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  XAesGcmKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.params().salt_size(), Eq(test_case.salt_size));
}

TEST_P(XAesGcmProtoSerializationTest, ParseKey) {
  const XAesGcmTestCase& test_case = GetParam();
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_salt_size(test_case.salt_size);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<XAesGcmParameters> expected_parameters =
      XAesGcmParameters::Create(test_case.variant, kSaltSize);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<XAesGcmKey> expected_key = XAesGcmKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(XAesGcmProtoSerializationTest, ParseKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse XAesGcmKey proto")));
}

TEST_F(XAesGcmProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_salt_size(kSaltSize);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_F(XAesGcmProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.mutable_params()->set_salt_size(kSaltSize);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(XAesGcmProtoSerializationTest, ParseKeyWithInvalidSaltSize) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_salt_size(6);  // Invalid salt size.
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kSymmetric,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                     HasSubstr("Salt size must be between")));
}

TEST_F(XAesGcmProtoSerializationTest, ParseKeyWithInvalidKeyType) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  google::crypto::tink::XAesGcmKey key_proto;
  key_proto.set_version(0);
  key_proto.mutable_params()->set_salt_size(kSaltSize);
  key_proto.set_key_value(raw_key_bytes);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmKey", serialized_key,
          KeyMaterialTypeEnum::kSymmetric, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kNotFound));
}

TEST_P(XAesGcmProtoSerializationTest, SerializeKey) {
  XAesGcmTestCase test_case = GetParam();
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());

  absl::StatusOr<XAesGcmParameters> parameters =
      XAesGcmParameters::Create(test_case.variant, test_case.salt_size);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  absl::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(*key,
                                               InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::XAesGcmKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value().size(), Eq(kKeySize));
}

TEST_F(XAesGcmProtoSerializationTest, SerializeKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterXAesGcmProtoSerialization(), IsOk());
  absl::StatusOr<XAesGcmParameters> parameters = XAesGcmParameters::Create(
      XAesGcmParameters::Variant::kNoPrefix, kSaltSize);
  ASSERT_THAT(parameters, IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(kKeySize);
  absl::StatusOr<XAesGcmKey> key = XAesGcmKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(*key, /*token=*/absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
