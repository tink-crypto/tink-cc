// Copyright 2025 Google LLC
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

#include "tink/experimental/pqcrypto/kem/internal/cecpq2_proto_serialization_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "openssl/hrss.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_private_key.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Cecpq2AeadHkdfKeyFormat;
using ::google::crypto::tink::Cecpq2AeadHkdfParams;
using ::google::crypto::tink::Cecpq2AeadHkdfPrivateKey;
using ::google::crypto::tink::Cecpq2AeadHkdfPublicKey;
using ::google::crypto::tink::Cecpq2HkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPublicKey";

KeyTemplate GetXChaCha20Poly1305RawKeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305NoPrefixParameters() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return *parameters;
}

Cecpq2AeadHkdfKeyFormat CreateKeyFormatProto(
    absl::optional<absl::string_view> salt) {
  Cecpq2HkdfKemParams kem_params_proto;
  kem_params_proto.set_curve_type(EllipticCurveType::CURVE25519);
  kem_params_proto.set_ec_point_format(EcPointFormat::COMPRESSED);
  kem_params_proto.set_hkdf_hash_type(HashType::SHA256);
  if (salt.has_value()) {
    kem_params_proto.set_hkdf_salt(*salt);
  }

  Cecpq2AeadHkdfParams params_proto;
  *params_proto.mutable_kem_params() = kem_params_proto;
  *params_proto.mutable_dem_params()->mutable_aead_dem() =
      GetXChaCha20Poly1305RawKeyTemplate();

  Cecpq2AeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params_proto;

  return key_format_proto;
}

void ValidateExpectedProtoParams(
    const Cecpq2AeadHkdfParams& params,
    absl::optional<absl::string_view> expected_salt) {
  ASSERT_THAT(params.has_dem_params(), IsTrue());
  ASSERT_THAT(params.dem_params().has_aead_dem(), IsTrue());
  EXPECT_THAT(params.dem_params().aead_dem().type_url(),
              Eq(GetXChaCha20Poly1305RawKeyTemplate().type_url()));
  ASSERT_THAT(params.has_kem_params(), IsTrue());
  EXPECT_THAT(params.kem_params().curve_type(),
              Eq(EllipticCurveType::CURVE25519));
  EXPECT_THAT(params.kem_params().ec_point_format(),
              Eq(EcPointFormat::COMPRESSED));
  EXPECT_THAT(params.kem_params().hkdf_hash_type(), Eq(HashType::SHA256));
  if (expected_salt.has_value()) {
    EXPECT_THAT(params.kem_params().hkdf_salt(), Eq(*expected_salt));
  } else {
    EXPECT_THAT(params.kem_params().hkdf_salt(), Eq(""));
  }
}

void ValidateExpectedProtoPublicKey(
    const Cecpq2AeadHkdfPublicKey& public_key,
    absl::optional<absl::string_view> expected_salt,
    absl::string_view expected_x25519_public_key_bytes,
    absl::string_view expected_hrss_public_key_bytes) {
  ASSERT_THAT(public_key.has_params(), IsTrue());
  ValidateExpectedProtoParams(public_key.params(), expected_salt);
  EXPECT_THAT(public_key.version(), Eq(0));
  EXPECT_THAT(public_key.x25519_public_key_x(),
              Eq(expected_x25519_public_key_bytes));
  EXPECT_THAT(public_key.x25519_public_key_y(), Eq(""));
  EXPECT_THAT(public_key.hrss_public_key_marshalled(),
              Eq(expected_hrss_public_key_bytes));
}

void ValidateExpectedProtoPrivateKey(
    const Cecpq2AeadHkdfPrivateKey& private_key,
    absl::optional<absl::string_view> expected_salt,
    absl::string_view expected_x25519_public_key_bytes,
    absl::string_view expected_hrss_public_key_bytes,
    absl::string_view expected_x25519_private_key_bytes,
    absl::string_view expected_hrss_private_key_bytes) {
  ASSERT_THAT(private_key.has_public_key(), IsTrue());
  ValidateExpectedProtoPublicKey(private_key.public_key(), expected_salt,
                                 expected_x25519_public_key_bytes,
                                 expected_hrss_public_key_bytes);
  EXPECT_THAT(private_key.version(), Eq(0));
  EXPECT_THAT(private_key.x25519_private_key(),
              Eq(expected_x25519_private_key_bytes));
  EXPECT_THAT(private_key.hrss_private_key_seed(),
              Eq(expected_hrss_private_key_bytes));
}

struct TestCase {
  Cecpq2Parameters::Variant variant;
  absl::optional<std::string> salt;
  OutputPrefixTypeEnum output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using Cecpq2ProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(Cecpq2ProtoSerializationTest, RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(Cecpq2ProtoSerializationTest, RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    Cecpq2ProtoSerializationTestSuite, Cecpq2ProtoSerializationTest,
    Values(TestCase{Cecpq2Parameters::Variant::kTink, /*salt=*/"salt",
                    OutputPrefixTypeEnum::kTink, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{Cecpq2Parameters::Variant::kNoPrefix,
                    /*salt=*/absl::nullopt, OutputPrefixTypeEnum::kRaw,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(Cecpq2ProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          CreateKeyFormatProto(test_case.salt).SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(),
              Eq(test_case.id_requirement.has_value()));

  const Cecpq2Parameters* cecpq2_params =
      dynamic_cast<const Cecpq2Parameters*>(params->get());
  ASSERT_THAT(cecpq2_params, NotNull());
  EXPECT_THAT(cecpq2_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cecpq2_params->GetSalt(), Eq(test_case.salt));
  EXPECT_THAT(cecpq2_params->GetDemParameters(),
              Eq(GetXChaCha20Poly1305NoPrefixParameters()));
}

TEST_P(Cecpq2ProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          CreateKeyFormatProto(test_case.salt).SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(),
              Eq(test_case.id_requirement.has_value()));

  const Cecpq2Parameters* cecpq2_params =
      dynamic_cast<const Cecpq2Parameters*>(params->get());
  ASSERT_THAT(cecpq2_params, NotNull());
  EXPECT_THAT(cecpq2_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(cecpq2_params->GetSalt(), Eq(test_case.salt));
  EXPECT_THAT(cecpq2_params->GetDemParameters(),
              Eq(GetXChaCha20Poly1305NoPrefixParameters()));
}

TEST_F(Cecpq2ProtoSerializationTest, ParseParametersWithPrefixedDemParameters) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  KeyTemplate prefixed_dem_key_template = GetXChaCha20Poly1305RawKeyTemplate();
  prefixed_dem_key_template.set_output_prefix_type(OutputPrefixType::TINK);

  Cecpq2AeadHkdfKeyFormat key_format_proto = CreateKeyFormatProto("salt");
  *key_format_proto.mutable_params()->mutable_dem_params()->mutable_aead_dem() =
      prefixed_dem_key_template;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsTrue());

  const Cecpq2Parameters* cecpq2_params =
      dynamic_cast<const Cecpq2Parameters*>(params->get());
  ASSERT_THAT(cecpq2_params, NotNull());
  // DEM key template has a Tink prefix but it is parsed as no-prefix.
  EXPECT_THAT(cecpq2_params->GetDemParameters(),
              Eq(GetXChaCha20Poly1305NoPrefixParameters()));
}

TEST_F(Cecpq2ProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Cecpq2ProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          CreateKeyFormatProto("salt").SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine Cecpq2Parameters::Variant")));
}

TEST_P(Cecpq2ProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kPrivateTypeUrl));
  EXPECT_THAT(
      key_template.output_prefix_type,
      Eq(static_cast<OutputPrefixTypeEnum>(test_case.output_prefix_type)));

  Cecpq2AeadHkdfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  ValidateExpectedProtoParams(key_format.params(), test_case.salt);
}

TEST_P(Cecpq2ProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kPrivateTypeUrl));
  EXPECT_THAT(
      key_template.output_prefix_type,
      Eq(static_cast<OutputPrefixTypeEnum>(test_case.output_prefix_type)));

  Cecpq2AeadHkdfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  ValidateExpectedProtoParams(key_format.params(), test_case.salt);
}

TEST_P(Cecpq2ProtoSerializationTest, ParsePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(test_case.salt).params();
  public_key_proto.set_x25519_public_key_x(x25519_public_key_bytes);
  public_key_proto.set_hrss_public_key_marshalled(hrss_public_key_bytes);
  RestrictedData serialized_public_key = RestrictedData(
      public_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_public_key,
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

  absl::StatusOr<Cecpq2Parameters> expected_parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_public_key));
}

TEST_P(Cecpq2ProtoSerializationTest, ParsePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder registry_builder;
  ASSERT_THAT(
      RegisterCecpq2ProtoSerializationWithRegistryBuilder(registry_builder),
      IsOk());
  SerializationRegistry registry = std::move(registry_builder).Build();

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(test_case.salt).params();
  public_key_proto.set_x25519_public_key_x(x25519_public_key_bytes);
  public_key_proto.set_hrss_public_key_marshalled(hrss_public_key_bytes);
  RestrictedData serialized_public_key = RestrictedData(
      public_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_public_key,
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

  absl::StatusOr<Cecpq2Parameters> expected_parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_public_key));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    KeyMaterialTypeEnum::kAsymmetricPublic,
                                    OutputPrefixTypeEnum::kTink,
                                    /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(1);  // Invalid version.
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(/*salt=*/absl::nullopt).params();
  public_key_proto.set_x25519_public_key_x(x25519_public_key_bytes);
  public_key_proto.set_hrss_public_key_marshalled(hrss_public_key_bytes);
  RestrictedData serialized_public_key = RestrictedData(
      public_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_public_key,
          KeyMaterialTypeEnum::kAsymmetricPublic,
          /*output_prefix_type=*/OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePublicKeyWithNonEmptyYCoordinate) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(/*salt=*/absl::nullopt).params();
  public_key_proto.set_x25519_public_key_x(x25519_public_key_bytes);
  public_key_proto.set_x25519_public_key_y("non-empty y-coordinate");
  public_key_proto.set_hrss_public_key_marshalled(hrss_public_key_bytes);
  RestrictedData serialized_public_key = RestrictedData(
      public_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_public_key,
          KeyMaterialTypeEnum::kAsymmetricPublic,
          /*output_prefix_type=*/OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Cecpq2AeadHkdfPublicKey.x25519_public_key_y must be empty")));
}

TEST_P(Cecpq2ProtoSerializationTest, SerializePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::Cecpq2AeadHkdfPublicKey public_key_proto;
  ASSERT_THAT(public_key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  ValidateExpectedProtoPublicKey(public_key_proto, test_case.salt,
                                 x25519_public_key_bytes,
                                 hrss_public_key_bytes);
}

TEST_P(Cecpq2ProtoSerializationTest, SerializePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder registry_builder;
  ASSERT_THAT(
      RegisterCecpq2ProtoSerializationWithRegistryBuilder(registry_builder),
      IsOk());
  SerializationRegistry registry = std::move(registry_builder).Build();

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(X25519KeyPubKeySize());
  std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*public_key,
                                                   /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(),
              Eq(test_case.id_requirement));

  google::crypto::tink::Cecpq2AeadHkdfPublicKey public_key_proto;
  ASSERT_THAT(public_key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  ValidateExpectedProtoPublicKey(public_key_proto, test_case.salt,
                                 x25519_public_key_bytes,
                                 hrss_public_key_bytes);
}

TEST_P(Cecpq2ProtoSerializationTest, ParsePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(test_case.salt).params();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
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

  absl::StatusOr<Cecpq2Parameters> expected_parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> expected_private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_P(Cecpq2ProtoSerializationTest, ParsePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder registry_builder;
  ASSERT_THAT(
      RegisterCecpq2ProtoSerializationWithRegistryBuilder(registry_builder),
      IsOk());
  SerializationRegistry registry = std::move(registry_builder).Build();

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() =
      CreateKeyFormatProto(test_case.salt).params();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
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

  absl::StatusOr<Cecpq2Parameters> expected_parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(expected_parameters, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*expected_parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> expected_public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> expected_private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_private_key =
      RestrictedData("invalid serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePrivateKeyWithoutPublicKey) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key, Not(IsOk()));
}

TEST_F(Cecpq2ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(1);  // Invalid version.
  *public_key_proto.mutable_params() = CreateKeyFormatProto("salt").params();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key, StatusIs(absl::StatusCode::kInvalidArgument,
                            HasSubstr("Only version 0 keys are accepted for "
                                      "Cecpq2AeadHkdfPublicKey proto")));
}

TEST_F(Cecpq2ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPrivateKeyVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = CreateKeyFormatProto("salt").params();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(1);  // Invalid version.
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key, StatusIs(absl::StatusCode::kInvalidArgument,
                            HasSubstr("Only version 0 keys are accepted for "
                                      "Cecpq2AeadHkdfPrivateKey proto")));
}

TEST_F(Cecpq2ProtoSerializationTest, ParsePrivateKeyWithNoSecretKeyAcess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = CreateKeyFormatProto("salt").params();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_private_key,
                                    KeyMaterialTypeEnum::kAsymmetricPrivate,
                                    OutputPrefixTypeEnum::kRaw,
                                    /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key, StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(Cecpq2ProtoSerializationTest, SerializePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *private_key, InsecureSecretKeyAccess::Get());
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

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  ASSERT_THAT(private_key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  ValidateExpectedProtoPrivateKey(
      private_key_proto, test_case.salt, cecpq2_key_pair->x25519_key_pair.pub_x,
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled,
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv),
      util::SecretDataAsStringView(
          cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
}

TEST_P(Cecpq2ProtoSerializationTest, SerializePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder registry_builder;
  ASSERT_THAT(
      RegisterCecpq2ProtoSerializationWithRegistryBuilder(registry_builder),
      IsOk());
  SerializationRegistry registry = std::move(registry_builder).Build();

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(),
                               test_case.salt, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2PublicKey::Builder builder =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);
  if (test_case.id_requirement.has_value()) {
    builder.SetIdRequirement(*test_case.id_requirement);
  }
  absl::StatusOr<Cecpq2PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *private_key, InsecureSecretKeyAccess::Get());
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

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  ASSERT_THAT(private_key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  ValidateExpectedProtoPrivateKey(
      private_key_proto, test_case.salt, cecpq2_key_pair->x25519_key_pair.pub_x,
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled,
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv),
      util::SecretDataAsStringView(
          cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
}

TEST_F(Cecpq2ProtoSerializationTest, SerializePrivateKeyWithNoSecreKeytAcess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterCecpq2ProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<Cecpq2Parameters> parameters =
      Cecpq2Parameters::Create(GetXChaCha20Poly1305NoPrefixParameters(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*parameters)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData x25519_private_key_bytes(cecpq2_key_pair->x25519_key_pair.priv,
                                          InsecureSecretKeyAccess::Get());
  RestrictedData hrss_private_key_seed(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(x25519_private_key_bytes)
          .SetHrssPrivateKeySeed(hrss_private_key_seed)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*private_key,
                                                   /*token=*/absl::nullopt);
  EXPECT_THAT(serialization, StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
