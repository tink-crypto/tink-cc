// Copyright 2023 Google LLC
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

#include "tink/hybrid/internal/hpke_proto_serialization_impl.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/serialization_registry.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/internal/testing/hpke_test_vectors.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/testing/equals_proto_key_serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::proto_testing::EqualsProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::util::SecretDataFromStringView;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkeParams;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.HpkePrivateKey";

struct TestCase {
  HpkeParameters::Variant variant;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  google::crypto::tink::internal::OutputPrefixTypeTP output_prefix_type;
  HpkeKem kem;
  HpkeKdf kdf;
  HpkeAead aead;
  std::optional<int> id;
  std::string output_prefix;
  subtle::EllipticCurveType curve;
};

using HpkeProtoSerializationTest = TestWithParam<TestCase>;

TEST_F(HpkeProtoSerializationTest, RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());
}

TEST_F(HpkeProtoSerializationTest, RegisterTwiceSucceedsWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    HpkeProtoSerializationTestSuite, HpkeProtoSerializationTest,
    Values(
        TestCase{HpkeParameters::Variant::kTink,
                 HpkeParameters::KemId::kDhkemP256HkdfSha256,
                 HpkeParameters::KdfId::kHkdfSha256,
                 HpkeParameters::AeadId::kAesGcm128,
                 google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
                 HpkeKem::DHKEM_P256_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                 HpkeAead::AES_128_GCM, /*id=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5),
                 subtle::EllipticCurveType::NIST_P256},
        TestCase{HpkeParameters::Variant::kCrunchy,
                 HpkeParameters::KemId::kDhkemP384HkdfSha384,
                 HpkeParameters::KdfId::kHkdfSha384,
                 HpkeParameters::AeadId::kAesGcm256,
                 google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy,
                 HpkeKem::DHKEM_P384_HKDF_SHA384, HpkeKdf::HKDF_SHA384,
                 HpkeAead::AES_256_GCM,
                 /*id=*/0x01030005,
                 /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5),
                 subtle::EllipticCurveType::NIST_P384},
        TestCase{HpkeParameters::Variant::kCrunchy,
                 HpkeParameters::KemId::kDhkemP521HkdfSha512,
                 HpkeParameters::KdfId::kHkdfSha512,
                 HpkeParameters::AeadId::kAesGcm256,
                 google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy,
                 HpkeKem::DHKEM_P521_HKDF_SHA512, HpkeKdf::HKDF_SHA512,
                 HpkeAead::AES_256_GCM,
                 /*id=*/0x07080910,
                 /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5),
                 subtle::EllipticCurveType::NIST_P521},
        TestCase{HpkeParameters::Variant::kNoPrefix,
                 HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                 HpkeParameters::KdfId::kHkdfSha256,
                 HpkeParameters::AeadId::kChaCha20Poly1305,
                 google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
                 HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                 HpkeAead::CHACHA20_POLY1305,
                 /*id=*/std::nullopt, /*output_prefix=*/"",
                 subtle::EllipticCurveType::CURVE25519}));

TEST_P(HpkeProtoSerializationTest, ParseParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(hpke_parameters->GetKemId(), Eq(test_case.kem_id));
  EXPECT_THAT(hpke_parameters->GetKdfId(), Eq(test_case.kdf_id));
  EXPECT_THAT(hpke_parameters->GetAeadId(), Eq(test_case.aead_id));
}

TEST_P(HpkeProtoSerializationTest, ParseParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(hpke_parameters->GetKemId(), Eq(test_case.kem_id));
  EXPECT_THAT(hpke_parameters->GetKdfId(), Eq(test_case.kdf_id));
  EXPECT_THAT(hpke_parameters->GetAeadId(), Eq(test_case.aead_id));
}

TEST_F(HpkeProtoSerializationTest, ParseLegacyAsCrunchy) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kLegacy,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), IsTrue());

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(),
              Eq(HpkeParameters::Variant::kCrunchy));
  EXPECT_THAT(hpke_parameters->GetKemId(),
              Eq(HpkeParameters::KemId::kDhkemX25519HkdfSha256));
  EXPECT_THAT(hpke_parameters->GetKdfId(),
              Eq(HpkeParameters::KdfId::kHkdfSha256));
  EXPECT_THAT(hpke_parameters->GetAeadId(),
              Eq(HpkeParameters::AeadId::kChaCha20Poly1305));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
          "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKem) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::KEM_UNKNOWN);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKdf) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::KDF_UNKNOWN);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownAead) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::AEAD_UNKNOWN);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          kPrivateTypeUrl,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeProtoSerializationTest, SerializeParametersWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  HpkeKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(key_format.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(key_format.params().aead(), Eq(test_case.aead));
}

TEST_P(HpkeProtoSerializationTest, SerializeParametersWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const ProtoParametersSerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const google::crypto::tink::internal::KeyTemplateTP& key_template =
      proto_serialization->GetKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  HpkeKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(key_format.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(key_format.params().aead(), Eq(test_case.aead));
}

struct KeyPair {
  std::string public_key;
  std::string private_key;
};

absl::StatusOr<KeyPair> GenerateKeyPair(subtle::EllipticCurveType curve) {
  if (curve == subtle::EllipticCurveType::CURVE25519) {
    return KeyPair{X25519PublicValue(),
                   std::string(X25519SecretValue().GetSecret(
                       InsecureSecretKeyAccess::Get()))};
  }
  if (curve == subtle::EllipticCurveType::NIST_P256) {
    return KeyPair{P256PointAsString(), std::string(P256SecretValue().GetSecret(
                                            InsecureSecretKeyAccess::Get()))};
  }
  if (curve == subtle::EllipticCurveType::NIST_P384) {
    return KeyPair{P384PointAsString(), std::string(P384SecretValue().GetSecret(
                                            InsecureSecretKeyAccess::Get()))};
  }
  if (curve == subtle::EllipticCurveType::NIST_P521) {
    return KeyPair{P521PointAsString(), std::string(P521SecretValue().GetSecret(
                                            InsecureSecretKeyAccess::Get()))};
  }
  return absl::InvalidArgumentError("Unsupported curve");
}

TEST_P(HpkeProtoSerializationTest, ParsePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(key_pair->public_key);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    google::crypto::tink::internal::KeyDataTP::
                                        KeyMaterialTypeTP::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HpkePublicKey> expected_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_P(HpkeProtoSerializationTest, ParsePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_public_key(key_pair->public_key);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPublicTypeUrl, serialized_key,
                                    google::crypto::tink::internal::KeyDataTP::
                                        KeyMaterialTypeTP::kAsymmetricPublic,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HpkePublicKey> expected_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(HpkeProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_public_key(key_pair->public_key);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPublic,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeProtoSerializationTest, SerializePublicKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<HpkePublicKey> key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.public_key(), Eq(key_pair->public_key));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.params().aead(), Eq(test_case.aead));
}

TEST_P(HpkeProtoSerializationTest, SerializePublicKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<HpkePublicKey> key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const ProtoKeySerialization* proto_serialization =
      dynamic_cast<const ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.public_key(), Eq(key_pair->public_key));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.params().aead(), Eq(test_case.aead));
}

TEST_P(HpkeProtoSerializationTest, ParsePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    google::crypto::tink::internal::KeyDataTP::
                                        KeyMaterialTypeTP::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HpkePublicKey> expected_public_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> expected_private_key = HpkePrivateKey::Create(
      *expected_public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_P(HpkeProtoSerializationTest, ParsePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(kPrivateTypeUrl, serialized_key,
                                    google::crypto::tink::internal::KeyDataTP::
                                        KeyMaterialTypeTP::kAsymmetricPrivate,
                                    test_case.output_prefix_type, test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<HpkeParameters> expected_parameters =
      HpkeParameters::Builder()
          .SetVariant(test_case.variant)
          .SetKemId(test_case.kem_id)
          .SetKdfId(test_case.kdf_id)
          .SetAeadId(test_case.aead_id)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HpkePublicKey> expected_public_key =
      HpkePublicKey::Create(*expected_parameters, key_pair->public_key,
                            test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> expected_private_key = HpkePrivateKey::Create(
      *expected_public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithNoPublicKey) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Only version 0 keys are accepted.")));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidPublicKeyVersion) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(1);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Only version 0 public keys are accepted.")));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = params;
  public_key_proto.set_public_key(key_pair->public_key);

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_private_key(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
              kAsymmetricPrivate,
          google::crypto::tink::internal::OutputPrefixTypeTP::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(*serialization, /*token=*/std::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(HpkeProtoSerializationTest, SerializePrivateKeyWithMutableRegistry) {
  TestCase test_case = GetParam();
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePrivateKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.private_key(), Eq(key_pair->private_key));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.public_key().params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.public_key().params().aead(), Eq(test_case.aead));
  EXPECT_THAT(proto_key.public_key().public_key(), Eq(key_pair->public_key));
}

TEST_P(HpkeProtoSerializationTest, SerializePrivateKeyWithRegistryBuilder) {
  TestCase test_case = GetParam();
  SerializationRegistry::Builder builder;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithRegistryBuilder(builder),
              IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(test_case.curve);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
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
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeTP(),
              Eq(google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
                     kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeTP(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::HpkePrivateKey proto_key;
  // OSS proto library complains if input is not converted to a string.
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.private_key(), Eq(key_pair->private_key));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().kem(), Eq(test_case.kem));
  EXPECT_THAT(proto_key.public_key().params().kdf(), Eq(test_case.kdf));
  EXPECT_THAT(proto_key.public_key().params().aead(), Eq(test_case.aead));
  EXPECT_THAT(proto_key.public_key().public_key(), Eq(key_pair->public_key));
}

TEST_F(HpkeProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());

  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, key_pair->public_key, /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(*private_key,
                                                   /*token=*/std::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

struct KeyAndSerialization {
  KeyAndSerialization(absl::string_view test_name, std::shared_ptr<Key> key,
                      ProtoKeySerialization proto_key_serialization)
      : test_name(test_name),
        key(std::move(key)),
        proto_key_serialization(std::move(proto_key_serialization)) {}

  std::string test_name;
  std::shared_ptr<Key> key;
  ProtoKeySerialization proto_key_serialization;
};

using SerializationTest = TestWithParam<KeyAndSerialization>;
using ParseTest = TestWithParam<KeyAndSerialization>;

TEST_P(SerializationTest, SerializesCorrectly) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<ProtoKeySerialization>(
          *test_key.key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization.status(), IsOk());
  ProtoKeySerialization* proto_serialization =
      dynamic_cast<ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, Not(IsNull()));
  EXPECT_THAT(*proto_serialization,
              EqualsProtoKeySerialization(test_key.proto_key_serialization));
}

TEST_P(ParseTest, ParserCorrectly) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(RegisterHpkeProtoSerializationWithMutableRegistry(registry),
              IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key = registry.ParseKey(
      test_key.proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_TRUE(**key == *test_key.key);
}

KeyAndSerialization PrivateKeyAndSerializationNistP256() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P256_HKDF_SHA256),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(P256PointAsString())}),
       FieldWithNumber(3).IsString(
           P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PrivateKeyP256",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationNistP384() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP384HkdfSha384)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P384PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P384SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P384_HKDF_SHA384),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA384),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_256_GCM)}),
            FieldWithNumber(3).IsString(P384PointAsString())}),
       FieldWithNumber(3).IsString(
           P384SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PrivateKeyP384",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationNistP521() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP521HkdfSha512)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P521PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P521SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P521_HKDF_SHA512),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA512),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(P521PointAsString())}),
       FieldWithNumber(3).IsString(
           P521SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PrivateKeyP521",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationX25519() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, X25519PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, X25519SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_X25519_HKDF_SHA256),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA384),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_256_GCM)}),
            FieldWithNumber(3).IsString(X25519PublicValue())}),
       FieldWithNumber(3).IsString(
           X25519SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PrivateKeyX25519",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationXWing() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, XWingPublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, XWingSecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(google::crypto::tink::X_WING),
                 FieldWithNumber(2).IsVarint(google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(XWingPublicValue())}),
       FieldWithNumber(3).IsString(
           XWingSecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PrivateKeyXWing",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationMlKem768() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem768)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, MlKem768PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, MlKem768SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(google::crypto::tink::ML_KEM768),
                 FieldWithNumber(2).IsVarint(google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(MlKem768PublicValue())}),
       FieldWithNumber(3).IsString(
           MlKem768SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PrivateKeyMlKem768",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationMlKem1024() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem1024)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, MlKem1024PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, MlKem1024SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(google::crypto::tink::ML_KEM1024),
                 FieldWithNumber(2).IsVarint(google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(MlKem1024PublicValue())}),
       FieldWithNumber(3).IsString(
           MlKem1024SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PrivateKeyMlKem1024",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationTink() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P256_HKDF_SHA256),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(P256PointAsString())}),
       FieldWithNumber(3).IsString(
           P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kTink, 0x12341234);

  return KeyAndSerialization("PrivateKeyTink",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationCrunchy() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P256_HKDF_SHA256),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_128_GCM)}),
            FieldWithNumber(3).IsString(P256PointAsString())}),
       FieldWithNumber(3).IsString(
           P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy, 0x12341234);

  return KeyAndSerialization("PrivateKeyCrunchy",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationNistP256() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PublicKeyP256",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationNistP384() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP384HkdfSha384)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P384PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P384_HKDF_SHA384),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA384),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_256_GCM)}),
       FieldWithNumber(3).IsString(P384PointAsString())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PublicKeyP384",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationNistP521() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP521HkdfSha512)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha512)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P521PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P521_HKDF_SHA512),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA512),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P521PointAsString())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PublicKeyP521",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationX25519() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, X25519PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_X25519_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA384),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_256_GCM)}),
       FieldWithNumber(3).IsString(X25519PublicValue())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("PublicKeyX25519",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationXWing() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, XWingPublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(google::crypto::tink::X_WING),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(XWingPublicValue())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PublicKeyXWing",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationMlKem768() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem768)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, MlKem768PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(google::crypto::tink::ML_KEM768),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(MlKem768PublicValue())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PublicKeyMlKem768",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationMlKem1024() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kMlKem1024)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, MlKem1024PublicValue(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(google::crypto::tink::ML_KEM1024),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(MlKem1024PublicValue())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw,
      /*id_requirement=*/std::nullopt);

  return KeyAndSerialization("PublicKeyMlKem1024",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationTink() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kTink)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kTink, 0x12341234);

  return KeyAndSerialization("PublicKeyTink",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationCrunchy() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kCrunchy)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPublic,
      google::crypto::tink::internal::OutputPrefixTypeTP::kCrunchy, 0x12341234);

  return KeyAndSerialization("PublicKeyCrunchy",
                             std::make_shared<HpkePublicKey>(*public_key),
                             serialization);
}

// We check that some non-standard feature of proto are respected (unknown
// fields, overwritten fields, explicitly serialized versions)
KeyAndSerialization PrivateKeyWithNonStandardSerialization() {
  absl::StatusOr<HpkeParameters> parameters =
      HpkeParameters::Builder()
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePrivateKey",
      {/* version field with default value*/ FieldWithNumber(1).IsVarint(0),
       FieldWithNumber(2).IsSubMessage(
           {/*version field with wrong version, will be overwritten */
            FieldWithNumber(1).IsVarint(1),
            FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(
                     google::crypto::tink::DHKEM_P256_HKDF_SHA256),
                 FieldWithNumber(2).IsVarint(
                     ::google::crypto::tink::HKDF_SHA256),
                 FieldWithNumber(3).IsVarint(
                     ::google::crypto::tink::AES_128_GCM)}),
            /* overwrite version to 0 */
            FieldWithNumber(1).IsVarint(0),
            FieldWithNumber(4).IsString("Unknown field"),
            FieldWithNumber(3).IsString(P256PointAsString())}),
       FieldWithNumber(3).IsString(
           P256SecretValue().GetSecret(InsecureSecretKeyAccess::Get()))},
      google::crypto::tink::internal::KeyDataTP::KeyMaterialTypeTP::
          kAsymmetricPrivate,
      google::crypto::tink::internal::OutputPrefixTypeTP::kRaw, std::nullopt);

  return KeyAndSerialization("NonCanonicalSerialization",
                             std::make_shared<HpkePrivateKey>(*private_key),
                             serialization);
}

INSTANTIATE_TEST_SUITE_P(
    ParseTest, ParseTest,
    testing::Values(
        PrivateKeyAndSerializationNistP256(),
        PrivateKeyAndSerializationNistP384(),
        PrivateKeyAndSerializationNistP521(),
        PrivateKeyAndSerializationX25519(), PrivateKeyAndSerializationXWing(),
        PrivateKeyAndSerializationMlKem768(),
        PrivateKeyAndSerializationMlKem1024(), PrivateKeyAndSerializationTink(),
        PrivateKeyAndSerializationCrunchy(),
        PublicKeyAndSerializationNistP256(),
        PublicKeyAndSerializationNistP384(),
        PublicKeyAndSerializationNistP521(), PublicKeyAndSerializationX25519(),
        PublicKeyAndSerializationXWing(), PublicKeyAndSerializationMlKem768(),
        PublicKeyAndSerializationMlKem1024(), PublicKeyAndSerializationTink(),
        PublicKeyAndSerializationCrunchy(),
        PrivateKeyWithNonStandardSerialization()),
    [](testing::TestParamInfo<class KeyAndSerialization> info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(SerializationTest, SerializationTest,
                         testing::Values(PrivateKeyAndSerializationNistP256(),
                                         PrivateKeyAndSerializationNistP384(),
                                         PrivateKeyAndSerializationNistP521(),
                                         PrivateKeyAndSerializationX25519(),
                                         PrivateKeyAndSerializationXWing(),
                                         PrivateKeyAndSerializationMlKem768(),
                                         PrivateKeyAndSerializationMlKem1024(),
                                         PrivateKeyAndSerializationTink(),
                                         PrivateKeyAndSerializationCrunchy(),
                                         PublicKeyAndSerializationNistP256(),
                                         PublicKeyAndSerializationNistP384(),
                                         PublicKeyAndSerializationNistP521(),
                                         PublicKeyAndSerializationXWing(),
                                         PublicKeyAndSerializationMlKem768(),
                                         PublicKeyAndSerializationMlKem1024(),
                                         PublicKeyAndSerializationX25519(),
                                         PublicKeyAndSerializationTink(),
                                         PublicKeyAndSerializationCrunchy()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
