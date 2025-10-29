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

#include "tink/aead/legacy_kms_envelope_aead_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/legacy_kms_envelope_aead_key.h"
#include "tink/aead/legacy_kms_envelope_aead_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/kms_envelope.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesCtrKeyFormat;
using ::google::crypto::tink::AesCtrParams;
using ::google::crypto::tink::AesEaxKeyFormat;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesGcmSivKeyFormat;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::HmacParams;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::KmsEnvelopeAeadKey;
using ::google::crypto::tink::KmsEnvelopeAeadKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

const absl::string_view kKekUri = "some://arbitrary.key.uri?q=123#xyz";

KeyTemplate GetXChaCha20Poly1305KeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305Parameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return *parameters;
}

KeyTemplate GetAesGcmKeyTemplate() {
  AesGcmKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(16);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesGcmParameters GetAesGcmParameters() {
  absl::StatusOr<AesGcmParameters> parameters =
      AesGcmParameters::Builder()
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

KeyTemplate GetAesGcmSivKeyTemplate() {
  AesGcmSivKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(16);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.AesGcmSivKey");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesGcmSivParameters GetAesGcmSivParameters() {
  absl::StatusOr<AesGcmSivParameters> parameters = AesGcmSivParameters::Create(
      /*key_size_in_bytes=*/16, AesGcmSivParameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return *parameters;
}

KeyTemplate GetAesCtrHmacAeadKeyTemplate() {
  AesCtrHmacAeadKeyFormat key_format;
  HmacKeyFormat& hmac_key_format = *key_format.mutable_hmac_key_format();
  AesCtrKeyFormat& aes_ctr_key_format =
      *key_format.mutable_aes_ctr_key_format();

  HmacParams& hmac_params = *hmac_key_format.mutable_params();
  hmac_key_format.set_key_size(16);
  hmac_params.set_hash(HashType::SHA256);
  hmac_params.set_tag_size(32);
  hmac_key_format.set_version(0);

  AesCtrParams& aes_ctr_params = *aes_ctr_key_format.mutable_params();
  aes_ctr_params.set_iv_size(12);
  aes_ctr_key_format.set_key_size(16);

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesCtrHmacAeadParameters GetAesCtrHmacAeadParameters() {
  absl::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(16)
          .SetHmacKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(32)
          .SetHashType(AesCtrHmacAeadParameters::HashType::kSha256)
          .SetVariant(AesCtrHmacAeadParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

KeyTemplate GetAesEaxKeyTemplate() {
  AesEaxKeyFormat key_format;
  key_format.set_key_size(16);
  key_format.mutable_params()->set_iv_size(12);
  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesEaxKey");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesEaxParameters GetAesEaxParameters() {
  absl::StatusOr<AesEaxParameters> parameters =
      AesEaxParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesEaxParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters);
  return *parameters;
}

struct TestCase {
  LegacyKmsEnvelopeAeadParameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id;
  std::string output_prefix;
  LegacyKmsEnvelopeAeadParameters::DekParsingStrategy dek_parsing_strategy;
  std::shared_ptr<AeadParameters> dek_parameters;
  KeyTemplate dek_template;
};

class LegacyKmsEnvelopeAeadProtoSerializationTest
    : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(LegacyKmsEnvelopeAeadProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    LegacyKmsEnvelopeAeadProtoSerializationTestSuite,
    LegacyKmsEnvelopeAeadProtoSerializationTest,
    Values(
        TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kTink,
                 OutputPrefixTypeEnum::kTink,
                 /*id=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5),
                 LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                     kAssumeXChaCha20Poly1305,
                 absl::make_unique<XChaCha20Poly1305Parameters>(
                     GetXChaCha20Poly1305Parameters()),
                 GetXChaCha20Poly1305KeyTemplate()},
        TestCase{
            LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
            OutputPrefixTypeEnum::kRaw,
            /*id=*/absl::nullopt,
            /*output_prefix=*/"",
            LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesGcm,
            absl::make_unique<AesGcmParameters>(GetAesGcmParameters()),
            GetAesGcmKeyTemplate()},
        TestCase{
            LegacyKmsEnvelopeAeadParameters::Variant::kTink,
            OutputPrefixTypeEnum::kTink,
            /*id=*/0x01030005,
            /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5),
            LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                kAssumeAesGcmSiv,
            absl::make_unique<AesGcmSivParameters>(GetAesGcmSivParameters()),
            GetAesGcmSivKeyTemplate()},
        TestCase{LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
                 OutputPrefixTypeEnum::kRaw,
                 /*id=*/absl::nullopt,
                 /*output_prefix=*/"",
                 LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::
                     kAssumeAesCtrHmac,
                 absl::make_unique<AesCtrHmacAeadParameters>(
                     GetAesCtrHmacAeadParameters()),
                 GetAesCtrHmacAeadKeyTemplate()},
        TestCase{
            LegacyKmsEnvelopeAeadParameters::Variant::kNoPrefix,
            OutputPrefixTypeEnum::kRaw,
            /*id=*/absl::nullopt,
            /*output_prefix=*/"",
            LegacyKmsEnvelopeAeadParameters::DekParsingStrategy::kAssumeAesEax,
            absl::make_unique<AesEaxParameters>(GetAesEaxParameters()),
            GetAesEaxKeyTemplate()}));

TEST_P(LegacyKmsEnvelopeAeadProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());

  KmsEnvelopeAeadKeyFormat key_format_proto;
  key_format_proto.set_kek_uri(kKekUri);
  *key_format_proto.mutable_dek_template() = test_case.dek_template;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> expected_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(kKekUri, test_case.variant,
                                              test_case.dek_parsing_strategy,
                                              *test_case.dek_parameters);
  ASSERT_THAT(expected_parameters, IsOk());

  EXPECT_THAT(**parameters, Eq(*expected_parameters));
}

TEST_P(LegacyKmsEnvelopeAeadProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(kKekUri, test_case.variant,
                                              test_case.dek_parsing_strategy,
                                              *test_case.dek_parameters);
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

  KmsEnvelopeAeadKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.kek_uri(), Eq(kKekUri));
  EXPECT_THAT(key_format.dek_template().type_url(),
              Eq(test_case.dek_template.type_url()));
}

TEST_P(LegacyKmsEnvelopeAeadProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());

  KmsEnvelopeAeadKeyFormat key_format_proto;
  key_format_proto.set_kek_uri(kKekUri);
  *key_format_proto.mutable_dek_template() = test_case.dek_template;
  KmsEnvelopeAeadKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_params() = key_format_proto;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kRemote,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> expected_parameters =
      LegacyKmsEnvelopeAeadParameters::Create(kKekUri, test_case.variant,
                                              test_case.dek_parsing_strategy,
                                              *test_case.dek_parameters);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> expected_key =
      LegacyKmsEnvelopeAeadKey::Create(*expected_parameters, test_case.id);
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(LegacyKmsEnvelopeAeadProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterLegacyKmsEnvelopeAeadProtoSerialization(), IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadParameters> parameters =
      LegacyKmsEnvelopeAeadParameters::Create(kKekUri, test_case.variant,
                                              test_case.dek_parsing_strategy,
                                              *test_case.dek_parameters);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<LegacyKmsEnvelopeAeadKey> key =
      LegacyKmsEnvelopeAeadKey::Create(*parameters, test_case.id);
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(*key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kRemote));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  KmsEnvelopeAeadKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.params().kek_uri(), Eq(kKekUri));
  EXPECT_THAT(proto_key.params().dek_template().type_url(),
              Eq(test_case.dek_template.type_url()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
