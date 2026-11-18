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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/chacha20_poly1305_parameters.h"
#include "tink/aead/internal/aes_eax_proto_serialization_impl.h"
#include "tink/aead/internal/chacha20_poly1305_proto_serialization_impl.h"
#include "tink/aead/internal/legacy_kms_aead_proto_serialization_impl.h"
#include "tink/aead/internal/testing/aes_ctr_hmac_aead_test_vectors.h"
#include "tink/aead/internal/testing/aes_eax_test_vectors.h"
#include "tink/aead/internal/testing/aes_gcm_siv_test_vectors.h"
#include "tink/aead/internal/testing/aes_gcm_test_vectors.h"
#include "tink/aead/internal/testing/chacha20_poly1305_test_vectors.h"
#include "tink/aead/internal/testing/x_aes_gcm_test_vectors.h"
#include "tink/aead/internal/testing/xchacha20_poly1305_test_vectors.h"
#include "tink/aead/internal/x_aes_gcm_proto_serialization_impl.h"
#include "tink/aead/internal/xchacha20_poly1305_proto_serialization_impl.h"
#include "tink/aead/legacy_kms_aead_parameters.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/daead/aes_siv_parameters.h"
#include "tink/daead/internal/aes_siv_test_vectors.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_struct_conversions.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/aes_cmac_proto_serialization_impl.h"
#include "tink/mac/internal/aes_cmac_test_vectors.h"
#include "tink/mac/internal/hmac_test_vectors.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/internal/aes_cmac_prf_proto_serialization_impl.h"
#include "tink/prf/internal/aes_cmac_prf_test_vectors.h"
#include "tink/prf/internal/hkdf_prf_test_vectors.h"
#include "tink/prf/internal/hmac_prf_proto_serialization_impl.h"
#include "tink/prf/internal/hmac_prf_test_vectors.h"
#include "tink/prf/prf_key.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/ed25519_test_vectors.h"
#include "tink/signature/internal/testing/ml_dsa_test_vectors.h"
#include "tink/signature/internal/testing/slh_dsa_test_vectors.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"
#include "proto/tink.tinkpb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::KeyMaterialTypeTP;
using ::crypto::tink::internal::OutputPrefixTypeTP;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestParamInfo;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
constexpr absl::string_view kPrfKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.HkdfPrfKey";
constexpr absl::string_view kDerivedKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
constexpr absl::string_view kPrfKeyValue = "0123456789abcdef0123456789abcdef";

const SerializationRegistry& GetRegistry() {
  static const absl::NoDestructor<SerializationRegistry> kRegistry([] {
    SerializationRegistry registry;
    ABSL_CHECK_OK(
        RegisterPrfBasedKeyDerivationProtoSerializationWithRegistry(registry));
    return registry;
  }());
  return *kRegistry;
}

// Helper registry used to construct serialized inner KeyTemplate / KeyData
// protos from Parameters / Key objects for negative test cases.
const SerializationRegistry& GetHelperRegistry() {
  static const absl::NoDestructor<SerializationRegistry> kRegistry([] {
    SerializationRegistry registry;
    ABSL_CHECK_OK(
        RegisterXChaCha20Poly1305ProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterAesCmacPrfProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterHmacPrfProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterAesEaxProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(
        RegisterChaCha20Poly1305ProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(
        RegisterLegacyKmsAeadProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterXAesGcmProtoSerializationWithRegistry(registry));
    ABSL_CHECK_OK(RegisterAesCmacProtoSerializationWithRegistry(registry));
    return registry;
  }());
  return *kRegistry;
}

KeyTemplate ToKeyTemplate(const Parameters& parameters) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetHelperRegistry().SerializeParameters<ProtoParametersSerialization>(
          parameters);
  ABSL_CHECK_OK(serialization);
  const auto* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ABSL_CHECK_NE(proto_serialization, nullptr);
  return ToProtoKeyTemplate(proto_serialization->GetKeyTemplate());
}

KeyData ToKeyData(const Key& key) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetHelperRegistry().SerializeKey<ProtoKeySerialization>(
          key, GetInsecureSecretKeyAccessInternal());
  ABSL_CHECK_OK(serialization);
  const auto* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ABSL_CHECK_NE(proto_serialization, nullptr);
  KeyData key_data;
  key_data.set_type_url(proto_serialization->TypeUrl());
  key_data.set_value(proto_serialization->SerializedKeyProto().GetSecret(
      GetInsecureSecretKeyAccessInternal()));
  key_data.set_key_material_type(static_cast<KeyData::KeyMaterialType>(
      proto_serialization->GetKeyMaterialTypeTP()));
  return key_data;
}

KeyTemplate GetHkdfPrfKeyTemplate() {
  HkdfPrfKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(kPrfKeyValue.size());
  key_format.mutable_params()->set_hash(HashType::SHA256);
  KeyTemplate key_template;
  key_template.set_type_url(kPrfKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

HkdfPrfParameters GetHkdfPrfParameters() {
  absl::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      kPrfKeyValue.size(), HkdfPrfParameters::HashType::kSha256,
      /*salt=*/std::nullopt);
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

HkdfPrfKey GetHkdfPrfKey() {
  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      GetHkdfPrfParameters(),
      RestrictedData(kPrfKeyValue, GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(key);
  return *key;
}

KeyData GetHkdfPrfKeyData() {
  google::crypto::tink::HkdfPrfKey key;
  key.set_version(0);
  key.mutable_params()->set_hash(HashType::SHA256);
  key.set_key_value(kPrfKeyValue);
  KeyData key_data;
  key_data.set_type_url(kPrfKeyTypeUrl);
  key_data.set_value(key.SerializeAsString());
  key_data.set_key_material_type(KeyData::SYMMETRIC);
  return key_data;
}

KeyTemplate GetXChaCha20Poly1305KeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(kDerivedKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305Parameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

PrfBasedKeyDerivationParameters GetTestParameters() {
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetHkdfPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ABSL_CHECK_OK(parameters);
  return *parameters;
}

PrfBasedKeyDerivationKey GetTestKey() {
  absl::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(GetTestParameters(), GetHkdfPrfKey(),
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ABSL_CHECK_OK(key);
  return *key;
}

ProtoParametersSerialization CreateParametersSerialization(
    const KeyTemplate& prf_key_template,
    const KeyTemplate& derived_key_template,
    OutputPrefixTypeTP output_prefix_type) {
  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = prf_key_template;
  *key_format_proto.mutable_params()->mutable_derived_key_template() =
      derived_key_template;
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kTypeUrl, output_prefix_type, key_format_proto.SerializeAsString());
  ABSL_CHECK_OK(serialization);
  return *serialization;
}

ProtoKeySerialization CreateKeySerialization(
    const KeyData& prf_key_data, const KeyTemplate& derived_key_template,
    OutputPrefixTypeTP output_prefix_type, std::optional<int> id_requirement,
    uint32_t version = 0) {
  google::crypto::tink::PrfBasedDeriverKey key_proto;
  key_proto.set_version(version);
  *key_proto.mutable_prf_key() = prf_key_data;
  *key_proto.mutable_params()->mutable_derived_key_template() =
      derived_key_template;
  RestrictedData serialized_key(key_proto.SerializeAsString(),
                                GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    output_prefix_type, id_requirement);
  ABSL_CHECK_OK(serialization);
  return *serialization;
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     RegisterTwiceSucceedsWithRegistry) {
  // TODO(b/378091229): Consider disallowing duplicate registrations.
  SerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistry(registry),
      IsOk());
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistry(registry),
      IsOk());
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      GetHkdfPrfKeyTemplate(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink);

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsTrue());
  EXPECT_THAT(**params, Eq(GetTestParameters()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, ParseParametersWithRegistry) {
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      GetHkdfPrfKeyTemplate(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink);

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      GetRegistry().ParseParameters(serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsTrue());
  EXPECT_THAT(**params, Eq(GetTestParameters()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithInvalidSerialization) {
  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(kTypeUrl, OutputPrefixTypeTP::kRaw,
                                           "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      GetRegistry().ParseParameters(*serialization),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse PrfBasedDeriverKeyFormatTP")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithMismatchedOutputPrefix) {
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      GetHkdfPrfKeyTemplate(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kRaw);

  EXPECT_THAT(GetRegistry().ParseParameters(serialization),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsed output prefix type must match derived "
                                 "key output prefix type")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithUnknownOutputPrefix) {
  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();
  derived_key_template.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      GetHkdfPrfKeyTemplate(), derived_key_template,
      OutputPrefixTypeTP::kUnknownPrefix);

  EXPECT_THAT(
      GetRegistry().ParseParameters(serialization),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Could not determine XChaCha20Poly1305Parameters::Variant")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithInvalidPrfParameters) {
  HkdfPrfKeyFormat invalid_prf_key_format;
  invalid_prf_key_format.set_version(0);
  invalid_prf_key_format.set_key_size(15);
  invalid_prf_key_format.mutable_params()->set_hash(HashType::SHA256);
  KeyTemplate invalid_prf_key_template = GetHkdfPrfKeyTemplate();
  invalid_prf_key_template.set_value(
      invalid_prf_key_format.SerializeAsString());
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      invalid_prf_key_template, GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink);

  EXPECT_THAT(GetRegistry().ParseParameters(serialization),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size must be at least 16 bytes")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithNonRawPrfKeyTemplate) {
  KeyTemplate non_raw_prf_key_template = GetHkdfPrfKeyTemplate();
  non_raw_prf_key_template.set_output_prefix_type(OutputPrefixType::TINK);
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      non_raw_prf_key_template, GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink);

  EXPECT_THAT(
      GetRegistry().ParseParameters(serialization),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Output prefix type must be RAW for HkdfPrfParameters")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithInvalidPrfKeyTemplate) {
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      ToKeyTemplate(GetXChaCha20Poly1305Parameters()),
      GetXChaCha20Poly1305KeyTemplate(), OutputPrefixTypeTP::kTink);

  EXPECT_THAT(GetRegistry().ParseParameters(serialization),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported PRF parameters when parsing "
                                 "PrfBasedKeyDerivationParameters")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(
          GetTestParameters());
  ASSERT_THAT(serialization, IsOk());

  const auto* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(), Eq(OutputPrefixTypeTP::kTink));

  PrfBasedDeriverKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.prf_key_template().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_format.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeParametersWithRegistry) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetRegistry().SerializeParameters<ProtoParametersSerialization>(
          GetTestParameters());
  ASSERT_THAT(serialization, IsOk());

  const auto* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(), Eq(OutputPrefixTypeTP::kTink));

  PrfBasedDeriverKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(key_format.prf_key_template().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_format.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, ParseKeyWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
  ProtoKeySerialization serialization = CreateKeySerialization(
      GetHkdfPrfKeyData(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(serialization, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(**key, Eq(GetTestKey()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, ParseKeyWithRegistry) {
  ProtoKeySerialization serialization = CreateKeySerialization(
      GetHkdfPrfKeyData(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  absl::StatusOr<std::unique_ptr<Key>> key = GetRegistry().ParseKey(
      serialization, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(**key, Eq(GetTestKey()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseKeyWithInvalidSerialization) {
  RestrictedData serialized_key("invalid_serialization",
                                GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                    KeyMaterialTypeTP::kSymmetric,
                                    OutputPrefixTypeTP::kTink,
                                    /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(GetRegistry().ParseKey(*serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse PrfBasedDeriverKeyTP")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseKeyWithMismatchedOutputPrefix) {
  ProtoKeySerialization serialization = CreateKeySerialization(
      GetHkdfPrfKeyData(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kRaw, /*id_requirement=*/std::nullopt);

  EXPECT_THAT(
      GetRegistry().ParseKey(serialization,
                             GetInsecureSecretKeyAccessInternal()),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Parsed output prefix type must match derived key "
                         "output prefix type")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, ParseKeyNoSecretKeyAccess) {
  ProtoKeySerialization serialization = CreateKeySerialization(
      GetHkdfPrfKeyData(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  EXPECT_THAT(GetRegistry().ParseKey(serialization, /*token=*/std::nullopt),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseKeyWithInvalidPrfKeyData) {
  const KeyData invalid_prf_key_data =
      ToKeyData(*GetXChaCha20Poly1305TestVector(
                     XChaCha20Poly1305Parameters::Variant::kTink)
                     .aead_key);
  ProtoKeySerialization serialization = CreateKeySerialization(
      invalid_prf_key_data, GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  EXPECT_THAT(GetRegistry().ParseKey(serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported PRF key when parsing "
                                 "PrfBasedKeyDerivationKey")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, ParseKeyWithInvalidVersion) {
  ProtoKeySerialization serialization = CreateKeySerialization(
      GetHkdfPrfKeyData(), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123, /*version=*/1);

  EXPECT_THAT(GetRegistry().ParseKey(serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseKeyWithInvalidPrfKeySize) {
  google::crypto::tink::HkdfPrfKey invalid_prf_key;
  invalid_prf_key.set_version(0);
  invalid_prf_key.mutable_params()->set_hash(HashType::SHA256);
  invalid_prf_key.set_key_value("0123456789abcde");
  KeyData invalid_prf_key_data = GetHkdfPrfKeyData();
  invalid_prf_key_data.set_value(invalid_prf_key.SerializeAsString());
  ProtoKeySerialization serialization = CreateKeySerialization(
      invalid_prf_key_data, GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  EXPECT_THAT(GetRegistry().ParseKey(serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Key size must be at least 16 bytes")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeKeyWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          GetTestKey(), GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const auto* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(OutputPrefixTypeTP::kTink));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(123));

  google::crypto::tink::PrfBasedDeriverKey key_proto;
  ASSERT_THAT(key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      GetInsecureSecretKeyAccessInternal())),
              IsTrue());
  EXPECT_THAT(key_proto.version(), Eq(0));
  EXPECT_THAT(key_proto.prf_key().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_proto.prf_key().key_material_type(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(key_proto.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));

  google::crypto::tink::HkdfPrfKey hkdf_key;
  ASSERT_THAT(hkdf_key.ParseFromString(key_proto.prf_key().value()), IsTrue());
  EXPECT_THAT(hkdf_key.version(), Eq(0));
  EXPECT_THAT(hkdf_key.params().hash(), Eq(HashType::SHA256));
  EXPECT_THAT(hkdf_key.key_value(), Eq(kPrfKeyValue));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest, SerializeKeyWithRegistry) {
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetRegistry().SerializeKey<ProtoKeySerialization>(
          GetTestKey(), GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const auto* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(KeyMaterialTypeTP::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(OutputPrefixTypeTP::kTink));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(123));

  google::crypto::tink::PrfBasedDeriverKey key_proto;
  ASSERT_THAT(key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      GetInsecureSecretKeyAccessInternal())),
              IsTrue());
  EXPECT_THAT(key_proto.version(), Eq(0));
  EXPECT_THAT(key_proto.prf_key().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_proto.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeKeyNoSecretKeyAccess) {
  EXPECT_THAT(GetRegistry().SerializeKey<ProtoKeySerialization>(
                  GetTestKey(), /*token=*/std::nullopt),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

struct RoundTripTestCase {
  std::string test_name;
  // Non-owning pointers into static NoDestructor test vectors.
  const PrfKey* prf_key;
  const Parameters* derived_key_parameters;
};

std::vector<RoundTripTestCase> GetRoundTripTestCases() {
  const Parameters* xchacha_tink =
      &GetXChaCha20Poly1305TestVector(
           XChaCha20Poly1305Parameters::Variant::kTink)
           .aead_key->GetParameters();
  const Parameters* xchacha_raw =
      &GetXChaCha20Poly1305TestVector(
           XChaCha20Poly1305Parameters::Variant::kNoPrefix)
           .aead_key->GetParameters();
  const PrfKey* hkdf_sha256_salt =
      &GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha256).key;
  const PrfKey* hkdf_sha256_long_salt =
      &GetHkdfPrfTestVector(80, HkdfPrfParameters::HashType::kSha256).key;
  const PrfKey* hkdf_sha1_no_salt =
      &GetHkdfPrfTestVector(22, HkdfPrfParameters::HashType::kSha1).key;

  return {
      {"HkdfSha256SaltTink", hkdf_sha256_salt, xchacha_tink},
      {"HkdfSha256LongSaltRaw", hkdf_sha256_long_salt, xchacha_raw},
      {"HkdfSha1NoSaltTink", hkdf_sha1_no_salt, xchacha_tink},
      {"DerivedAesCtrHmacAead", hkdf_sha256_salt,
       &GetAesCtrHmacAeadTestVector(16,
                                    AesCtrHmacAeadParameters::Variant::kTink)
            .aead_key->GetParameters()},
      {"DerivedAesGcm", hkdf_sha256_salt,
       &GetAesGcmTestVector(16, AesGcmParameters::Variant::kTink)
            .aead_key->GetParameters()},
      {"DerivedAesGcmSiv", hkdf_sha256_salt,
       &GetAesGcmSivTestVector(16, AesGcmSivParameters::Variant::kTink)
            .aead_key->GetParameters()},
      {"DerivedAesSiv", hkdf_sha256_salt,
       &GetAesSivTestVector(32, AesSivParameters::Variant::kTink)
            .key.GetParameters()},
      {"DerivedHmac", hkdf_sha256_salt,
       &GetHmacTestVector(16, HmacParameters::HashType::kSha256,
                          HmacParameters::Variant::kNoPrefix)
            .key.GetParameters()},
      {"DerivedAesCmacPrf", hkdf_sha256_salt,
       &GetAesCmacPrfTestVector(16).key.GetParameters()},
      {"DerivedHkdfPrf", hkdf_sha256_salt, &hkdf_sha256_salt->GetParameters()},
      {"DerivedHmacPrf", hkdf_sha256_salt,
       &GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256)
            .key.GetParameters()},
      {"DerivedEcdsa", hkdf_sha256_salt,
       &GetEcdsaTestVector(EcdsaParameters::CurveType::kNistP521,
                           EcdsaParameters::HashType::kSha512,
                           EcdsaParameters::SignatureEncoding::kIeeeP1363,
                           EcdsaParameters::Variant::kNoPrefix)
            .signature_private_key->GetParameters()},
      {"DerivedEd25519", hkdf_sha256_salt,
       &GetEd25519TestVector(Ed25519Parameters::Variant::kNoPrefix)
            .signature_private_key->GetParameters()},
      {"DerivedMlDsa", hkdf_sha256_salt,
       &GetMlDsaTestVector(MlDsaParameters::Instance::kMlDsa87,
                           MlDsaParameters::Variant::kTink)
            .signature_private_key->GetParameters()},
      {"DerivedSlhDsa", hkdf_sha256_salt,
       &GetSlhDsaTestVector(SlhDsaParameters::HashType::kSha2,
                            SlhDsaParameters::SignatureType::kSmallSignature,
                            SlhDsaParameters::Variant::kTink)
            .signature_private_key->GetParameters()},
      {"DerivedAesCtrHmacStreaming", hkdf_sha256_salt,
       &GetAesCtrHmacStreamingTestVector(16)
            .streamingaead_key->GetParameters()},
      {"DerivedAesGcmHkdfStreaming", hkdf_sha256_salt,
       &GetAesGcmHkdfStreamingTestVector(16)
            .streamingaead_key->GetParameters()},
  };
}

using PrfBasedKeyDerivationRoundTripTest = TestWithParam<RoundTripTestCase>;

INSTANTIATE_TEST_SUITE_P(PrfBasedKeyDerivationRoundTripTests,
                         PrfBasedKeyDerivationRoundTripTest,
                         ValuesIn(GetRoundTripTestCases()),
                         [](const TestParamInfo<RoundTripTestCase>& info) {
                           return info.param.test_name;
                         });

TEST_P(PrfBasedKeyDerivationRoundTripTest, SerializeAndParseParameters) {
  const RoundTripTestCase& test_case = GetParam();
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(test_case.prf_key->GetParameters())
          .SetDerivedKeyParameters(*test_case.derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetRegistry().SerializeParameters<ProtoParametersSerialization>(
          *parameters);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      GetRegistry().ParseParameters(**serialization);
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(**parsed, Eq(*parameters));
}

TEST_P(PrfBasedKeyDerivationRoundTripTest, SerializeAndParseKey) {
  const RoundTripTestCase& test_case = GetParam();
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(test_case.prf_key->GetParameters())
          .SetDerivedKeyParameters(*test_case.derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::optional<int> id_requirement =
      test_case.derived_key_parameters->HasIdRequirement()
          ? std::optional<int>(123)
          : std::nullopt;
  absl::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *test_case.prf_key,
                                       id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      GetRegistry().SerializeKey<ProtoKeySerialization>(
          *key, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed = GetRegistry().ParseKey(
      **serialization, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(parsed, IsOk());
  EXPECT_THAT(**parsed, Eq(*key));
}

struct UnsupportedPrfTestCase {
  std::string test_name;
  // Non-owning pointer into static NoDestructor test vectors.
  const PrfKey* prf_key;
};

using PrfBasedKeyDerivationUnsupportedPrfTypesTest =
    TestWithParam<UnsupportedPrfTestCase>;

INSTANTIATE_TEST_SUITE_P(
    PrfBasedKeyDerivationUnsupportedPrfTypesTests,
    PrfBasedKeyDerivationUnsupportedPrfTypesTest,
    ValuesIn(std::vector<UnsupportedPrfTestCase>{
        {"AesCmacPrf", &GetAesCmacPrfTestVector(16).key},
        {"HmacPrf",
         &GetHmacPrfTestVector(40, HmacPrfParameters::HashType::kSha256).key},
    }),
    [](const TestParamInfo<UnsupportedPrfTestCase>& info) {
      return info.param.test_name;
    });

TEST_P(PrfBasedKeyDerivationUnsupportedPrfTypesTest, ParseParametersFails) {
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      ToKeyTemplate(GetParam().prf_key->GetParameters()),
      GetXChaCha20Poly1305KeyTemplate(), OutputPrefixTypeTP::kTink);

  EXPECT_THAT(GetRegistry().ParseParameters(serialization),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported PRF parameters when parsing "
                                 "PrfBasedKeyDerivationParameters")));
}

TEST_P(PrfBasedKeyDerivationUnsupportedPrfTypesTest, SerializeParametersFails) {
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetParam().prf_key->GetParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(GetRegistry().SerializeParameters<ProtoParametersSerialization>(
                  *parameters),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_P(PrfBasedKeyDerivationUnsupportedPrfTypesTest, ParseKeyFails) {
  ProtoKeySerialization serialization = CreateKeySerialization(
      ToKeyData(*GetParam().prf_key), GetXChaCha20Poly1305KeyTemplate(),
      OutputPrefixTypeTP::kTink, /*id_requirement=*/123);

  EXPECT_THAT(GetRegistry().ParseKey(serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported PRF key when parsing "
                                 "PrfBasedKeyDerivationKey")));
}

TEST_P(PrfBasedKeyDerivationUnsupportedPrfTypesTest, SerializeKeyFails) {
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetParam().prf_key->GetParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, *GetParam().prf_key,
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(GetRegistry().SerializeKey<ProtoKeySerialization>(
                  *key, GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kNotFound));
}

struct UnsupportedDerivedKeyTestCase {
  std::string test_name;
  // Non-owning pointer into static NoDestructor test vectors / parameters.
  const Parameters* derived_key_parameters;
};

std::vector<UnsupportedDerivedKeyTestCase> GetUnsupportedDerivedKeyTestCases() {
  static const absl::NoDestructor<LegacyKmsAeadParameters> kLegacyKmsAeadParams(
      [] {
        absl::StatusOr<LegacyKmsAeadParameters> params =
            LegacyKmsAeadParameters::Create(
                "key_uri", LegacyKmsAeadParameters::Variant::kTink);
        ABSL_CHECK_OK(params);
        return *params;
      }());

  return {
      {"AesEax", &GetAesEaxTestVector(16, AesEaxParameters::Variant::kTink)
                      .aead_key->GetParameters()},
      {"ChaCha20Poly1305", &GetChaCha20Poly1305TestVector(
                                ChaCha20Poly1305Parameters::Variant::kTink)
                                .aead_key->GetParameters()},
      {"LegacyKmsAead", kLegacyKmsAeadParams.get()},
      {"XAesGcm", &GetXAesGcmTestVector(8, XAesGcmParameters::Variant::kTink)
                       .aead_key->GetParameters()},
      {"AesCmac", &GetAesCmacTestVector(16).key.GetParameters()},
  };
}

using PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest =
    TestWithParam<UnsupportedDerivedKeyTestCase>;

INSTANTIATE_TEST_SUITE_P(
    PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTests,
    PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest,
    ValuesIn(GetUnsupportedDerivedKeyTestCases()),
    [](const TestParamInfo<UnsupportedDerivedKeyTestCase>& info) {
      return info.param.test_name;
    });

TEST_P(PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest,
       ParseParametersFails) {
  const KeyTemplate derived_key_template =
      ToKeyTemplate(*GetParam().derived_key_parameters);
  ProtoParametersSerialization serialization = CreateParametersSerialization(
      GetHkdfPrfKeyTemplate(), derived_key_template,
      static_cast<OutputPrefixTypeTP>(
          derived_key_template.output_prefix_type()));

  EXPECT_THAT(GetRegistry().ParseParameters(serialization),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported derived key parameters when "
                                 "parsing PrfBasedKeyDerivationParameters")));
}

TEST_P(PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest,
       SerializeParametersFails) {
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetHkdfPrfParameters())
          .SetDerivedKeyParameters(*GetParam().derived_key_parameters)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT(GetRegistry().SerializeParameters<ProtoParametersSerialization>(
                  *parameters),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_P(PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest, ParseKeyFails) {
  const Parameters& derived_params = *GetParam().derived_key_parameters;
  const KeyTemplate derived_key_template = ToKeyTemplate(derived_params);
  std::optional<int> id_requirement = derived_params.HasIdRequirement()
                                          ? std::optional<int>(123)
                                          : std::nullopt;
  ProtoKeySerialization serialization =
      CreateKeySerialization(GetHkdfPrfKeyData(), derived_key_template,
                             static_cast<OutputPrefixTypeTP>(
                                 derived_key_template.output_prefix_type()),
                             id_requirement);

  EXPECT_THAT(GetRegistry().ParseKey(serialization,
                                     GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported derived key parameters when "
                                 "parsing PrfBasedKeyDerivationParameters")));
}

TEST_P(PrfBasedKeyDerivationUnsupportedDerivedKeyTypesTest, SerializeKeyFails) {
  const Parameters& derived_params = *GetParam().derived_key_parameters;
  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetHkdfPrfParameters())
          .SetDerivedKeyParameters(derived_params)
          .Build();
  ASSERT_THAT(parameters, IsOk());
  std::optional<int> id_requirement = derived_params.HasIdRequirement()
                                          ? std::optional<int>(123)
                                          : std::nullopt;
  absl::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, GetHkdfPrfKey(),
                                       id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(GetRegistry().SerializeKey<ProtoKeySerialization>(
                  *key, GetInsecureSecretKeyAccessInternal()),
              StatusIs(absl::StatusCode::kNotFound));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
