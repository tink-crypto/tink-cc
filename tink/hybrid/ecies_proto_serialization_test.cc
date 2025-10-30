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

#include "tink/hybrid/ecies_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/internal/aes_ctr_hmac_proto_structs.h"
#include "tink/big_integer.h"
#include "tink/ec_point.h"
#include "tink/hybrid/ecies_parameters.h"
#include "tink/hybrid/ecies_private_key.h"
#include "tink/hybrid/ecies_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_siv.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::AesSivKeyFormat;
using ::google::crypto::tink::EciesAeadDemParams;
using ::google::crypto::tink::EciesAeadHkdfKeyFormat;
using ::google::crypto::tink::EciesAeadHkdfParams;
using ::google::crypto::tink::EciesAeadHkdfPrivateKey;
using ::google::crypto::tink::EciesAeadHkdfPublicKey;
using ::google::crypto::tink::EciesHkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";
const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";
constexpr absl::string_view kSalt = "2024ab";

struct TestCase {
  EciesParameters::Variant variant;
  EciesParameters::CurveType curve_type;
  EciesParameters::HashType hash_type;
  EciesParameters::DemId dem_id;
  absl::optional<EciesParameters::PointFormat> point_format;
  absl::optional<std::string> salt;
  OutputPrefixTypeEnum output_prefix_type;
  EciesHkdfKemParams kem_params;
  EciesAeadDemParams dem_params;
  EcPointFormat ec_point_format;
  absl::optional<int> id;
  std::string output_prefix;
};

class EciesProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  EciesProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(EciesProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());
}

EciesHkdfKemParams CreateKemParams(EllipticCurveType curve_type,
                                   HashType hash_type, absl::string_view salt) {
  EciesHkdfKemParams kem_params;
  kem_params.set_curve_type(curve_type);
  kem_params.set_hkdf_hash_type(hash_type);
  kem_params.set_hkdf_salt(salt);
  return kem_params;
}

EciesAeadDemParams CreateAesGcmDemParams(int key_size_in_bytes) {
  AesGcmKeyFormat format;
  format.set_key_size(key_size_in_bytes);
  format.set_version(0);

  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

EciesAeadDemParams CreateAes256SivDemParams() {
  AesSivKeyFormat format;
  format.set_key_size(64);
  format.set_version(0);

  KeyTemplate key_template;
  key_template.set_type_url("type.googleapis.com/google.crypto.tink.AesSivKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

EciesAeadDemParams CreateXChaCha20Poly1305DemParams() {
  XChaCha20Poly1305KeyFormat format;
  format.set_version(0);

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

EciesAeadDemParams CreateAesCtrHmacDemParams(
    absl::optional<int> aes_key_size, absl::optional<int> iv_size,
    absl::optional<int> version, absl::optional<int> hmac_key_size,
    absl::optional<int> tag_size,
    absl::optional<internal::HashTypeEnum> hash_type) {
  internal::ProtoAesCtrHmacAeadKeyFormat format;
  format.mutable_aes_ctr_key_format()->set_key_size(aes_key_size.value_or(0));
  format.mutable_aes_ctr_key_format()->mutable_params()->set_iv_size(
      iv_size.value_or(0));

  format.mutable_hmac_key_format()->set_version(version.value_or(0));
  format.mutable_hmac_key_format()->set_key_size(hmac_key_size.value_or(0));
  format.mutable_hmac_key_format()->mutable_params()->set_tag_size(
      tag_size.value_or(0));
  format.mutable_hmac_key_format()->mutable_params()->set_hash(
      hash_type.value_or(internal::HashTypeEnum::kUnknownHash));

  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  *key_template.mutable_value() = format.SerializeAsString();

  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;
  return dem_params;
}

EciesAeadDemParams CreateAesCtrHmacDemParams(int key_size) {
  // Key and tag sizes match for allowed AES-CTR-HMAC DEMs.
  return CreateAesCtrHmacDemParams(
      /*aes_key_size=*/key_size, /*iv_size=*/16,
      /*version=*/0, /*hmac_key_size=*/32,
      /*tag_size=*/key_size,
      /*hash_type=*/internal::HashTypeEnum::kSha256);
}

INSTANTIATE_TEST_SUITE_P(
    EciesProtoSerializationTestSuite, EciesProtoSerializationTest,
    Values(TestCase{EciesParameters::Variant::kTink,
                    EciesParameters::CurveType::kNistP256,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kAes128GcmRaw,
                    EciesParameters::PointFormat::kCompressed, kSalt.data(),
                    OutputPrefixTypeEnum::kTink,
                    CreateKemParams(EllipticCurveType::NIST_P256,
                                    HashType::SHA256, kSalt),
                    CreateAesGcmDemParams(16), EcPointFormat::COMPRESSED,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{EciesParameters::Variant::kCrunchy,
                    EciesParameters::CurveType::kNistP384,
                    EciesParameters::HashType::kSha384,
                    EciesParameters::DemId::kAes256GcmRaw,
                    EciesParameters::PointFormat::kLegacyUncompressed,
                    /*salt=*/absl::nullopt, OutputPrefixTypeEnum::kCrunchy,
                    CreateKemParams(EllipticCurveType::NIST_P384,
                                    HashType::SHA384, /*salt=*/""),
                    CreateAesGcmDemParams(32),
                    EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{EciesParameters::Variant::kTink,
                    EciesParameters::CurveType::kNistP521,
                    EciesParameters::HashType::kSha512,
                    EciesParameters::DemId::kAes256SivRaw,
                    EciesParameters::PointFormat::kUncompressed,
                    /*salt=*/absl::nullopt, OutputPrefixTypeEnum::kTink,
                    CreateKemParams(EllipticCurveType::NIST_P521,
                                    HashType::SHA512, /*salt=*/""),
                    CreateAes256SivDemParams(), EcPointFormat::UNCOMPRESSED,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{EciesParameters::Variant::kNoPrefix,
                    EciesParameters::CurveType::kX25519,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kXChaCha20Poly1305Raw,
                    /*point_format=*/absl::nullopt,
                    /*salt=*/kSalt.data(), OutputPrefixTypeEnum::kRaw,
                    CreateKemParams(EllipticCurveType::CURVE25519,
                                    HashType::SHA256, /*salt=*/kSalt),
                    CreateXChaCha20Poly1305DemParams(),
                    EcPointFormat::COMPRESSED,
                    /*id=*/absl::nullopt, /*output_prefix=*/""},
           TestCase{EciesParameters::Variant::kNoPrefix,
                    EciesParameters::CurveType::kX25519,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kAes128CtrHmacSha256Raw,
                    /*point_format=*/absl::nullopt,
                    /*salt=*/kSalt.data(), OutputPrefixTypeEnum::kRaw,
                    CreateKemParams(EllipticCurveType::CURVE25519,
                                    HashType::SHA256, /*salt=*/kSalt),
                    CreateAesCtrHmacDemParams(16), EcPointFormat::COMPRESSED,
                    /*id=*/absl::nullopt, /*output_prefix=*/""},
           TestCase{EciesParameters::Variant::kNoPrefix,
                    EciesParameters::CurveType::kX25519,
                    EciesParameters::HashType::kSha256,
                    EciesParameters::DemId::kAes256CtrHmacSha256Raw,
                    /*point_format=*/absl::nullopt,
                    /*salt=*/kSalt.data(), OutputPrefixTypeEnum::kRaw,
                    CreateKemParams(EllipticCurveType::CURVE25519,
                                    HashType::SHA256, /*salt=*/kSalt),
                    CreateAesCtrHmacDemParams(32), EcPointFormat::COMPRESSED,
                    /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(EciesProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = test_case.kem_params;
  *params.mutable_dem_params() = test_case.dem_params;
  params.set_ec_point_format(test_case.ec_point_format);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(ecies_parameters->GetCurveType(), Eq(test_case.curve_type));
  EXPECT_THAT(ecies_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(ecies_parameters->GetDemId(), Eq(test_case.dem_id));
  EXPECT_THAT(ecies_parameters->GetNistCurvePointFormat(),
              Eq(test_case.point_format));
  EXPECT_THAT(ecies_parameters->GetSalt(), Eq(test_case.salt));
}

TEST_F(EciesProtoSerializationTest, ParseLegacyAsCrunchySucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kLegacy,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetVariant(),
              Eq(EciesParameters::Variant::kCrunchy));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

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
               HasSubstr("Could not determine EciesParameters::Variant")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingKemFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingDemFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("proto DEM params")));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithMissingPointFormatFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EciesParameters::PointFormat")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingSaltSucceeds) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  params.mutable_kem_params()->clear_hkdf_salt();  // Missing salt.
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  const EciesParameters* ecies_parameters =
      dynamic_cast<const EciesParameters*>(parameters->get());
  ASSERT_THAT(ecies_parameters, NotNull());
  EXPECT_THAT(ecies_parameters->GetSalt(), Eq(absl::nullopt));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithMissingParamsFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfKeyFormat key_format_proto;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest,
       ParseParametersWithMissingKeyTemplateFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.mutable_dem_params()->clear_aead_dem();  // Missing key template.
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownCurveTypeFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = CreateKemParams(
      EllipticCurveType::UNKNOWN_CURVE, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EciesParameters::CurveType")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = CreateKemParams(EllipticCurveType::NIST_P256,
                                                 HashType::UNKNOWN_HASH, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EciesParameters::HashType")));
}

TEST_F(EciesProtoSerializationTest, ParseParametersWithUnkownPointFormatFails) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::UNKNOWN_FORMAT);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      parameters.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Could not determine EciesParameters::PointFormat")));
}

TEST_F(EciesProtoSerializationTest,
       ParseAesCtrHmacParamsWithMissingAesCtrKeyFormat) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesCtrHmacDemParams(
      /*aes_key_size=*/absl::nullopt, /*iv_size=*/absl::nullopt,
      /*version=*/0, /*hmac_key_size=*/32, /*tag_size=*/16,
      /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(EciesProtoSerializationTest,
       ParseAesCtrHmacParamsWithMissingAesCtrParams) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/absl::nullopt,
                                /*version=*/0, /*hmac_key_size=*/32,
                                /*tag_size=*/16,
                                /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(EciesProtoSerializationTest, ParseAesCtrHmacParamsWithInvalidIv) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/14,
                                /*version=*/0, /*hmac_key_size=*/32,
                                /*tag_size=*/16,
                                /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("IV size must be 16 bytes")));
}

TEST_F(EciesProtoSerializationTest,
       ParseAesCtrHmacParamsWithMissingHmacKeyFormat) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesCtrHmacDemParams(
      /*aes_key_size=*/16, /*iv_size=*/16,
      /*version=*/absl::nullopt, /*hmac_key_size=*/absl::nullopt,
      /*tag_size=*/absl::nullopt, /*hash_type=*/absl::nullopt);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(EciesProtoSerializationTest,
       ParseAesCtrHmacParamsWithInvalidHmacKeySize) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/16,
                                /*version=*/0, /*hmac_key_size=*/30,
                                /*tag_size=*/16,
                                /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HMAC key size must be 32 bytes")));
}

TEST_F(EciesProtoSerializationTest,
       ParseAesCtrHmacParamsWithMissingHmacParams) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesCtrHmacDemParams(
      /*aes_key_size=*/16, /*iv_size=*/16, /*version=*/0, /*hmac_key_size=*/32,
      /*tag_size=*/absl::nullopt, /*hash_type=*/absl::nullopt);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(EciesProtoSerializationTest, ParseAesCtrHmacParamsWithInvalidHashType) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/16,
                                /*version=*/0, /*hmac_key_size=*/32,
                                /*tag_size=*/16,
                                /*hash_type=*/internal::HashTypeEnum::kSha1);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Hash type must be SHA256")));
}

TEST_F(EciesProtoSerializationTest, ParseAesCtrHmacParamsWithInvalidVersion) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/16,
                                /*version=*/1, /*hmac_key_size=*/32,
                                /*tag_size=*/16,
                                /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("HMAC key format version must be 0")));
}

TEST_F(EciesProtoSerializationTest, ParseAesCtrHmacParamsWithMismatchedSizes) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  // AES key size and HMAC tag size should match for allowed AES-CTR-HMAC DEMs.
  *params.mutable_dem_params() =
      CreateAesCtrHmacDemParams(/*aes_key_size=*/16, /*iv_size=*/16,
                                /*version=*/0, /*hmac_key_size=*/32,
                                /*tag_size=*/32,
                                /*hash_type=*/internal::HashTypeEnum::kSha256);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Allowed AES-CTR-HMAC DEMs must have matching "
                                 "key and tag sizes")));
}

TEST_P(EciesProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  absl::StatusOr<EciesParameters> parameters = parameters_builder.Build();
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
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(test_case.output_prefix_type));

  EciesAeadHkdfKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());
  ASSERT_THAT(key_format.has_params(), IsTrue());

  ASSERT_THAT(key_format.params().has_kem_params(), IsTrue());
  EXPECT_THAT(key_format.params().kem_params().curve_type(),
              Eq(test_case.kem_params.curve_type()));
  EXPECT_THAT(key_format.params().kem_params().hkdf_hash_type(),
              Eq(test_case.kem_params.hkdf_hash_type()));
  EXPECT_THAT(key_format.params().kem_params().hkdf_salt(),
              Eq(test_case.kem_params.hkdf_salt()));

  ASSERT_THAT(key_format.params().has_dem_params(), IsTrue());
  ASSERT_THAT(key_format.params().dem_params().has_aead_dem(), IsTrue());
  EXPECT_THAT(key_format.params().dem_params().aead_dem().type_url(),
              Eq(test_case.dem_params.aead_dem().type_url()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().output_prefix_type(),
              Eq(test_case.dem_params.aead_dem().output_prefix_type()));
  EXPECT_THAT(key_format.params().dem_params().aead_dem().value(),
              Eq(test_case.dem_params.aead_dem().value()));
  EXPECT_THAT(key_format.params().ec_point_format(),
              Eq(test_case.ec_point_format));
}

struct KeyPair {
  // Public key coordinates
  std::string x;
  std::string y;  // Empty for X25519 public keys.
  std::string private_key;
};

absl::StatusOr<KeyPair> GenerateKeyPair(subtle::EllipticCurveType curve) {
  if (curve == subtle::EllipticCurveType::CURVE25519) {
    absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
        internal::NewX25519Key();
    if (!x25519_key.ok()) {
      return x25519_key.status();
    }
    const std::string public_key_bytes =
        std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                    internal::X25519KeyPubKeySize());
    const std::string private_key_bytes =
        std::string(util::SecretDataAsStringView((*x25519_key)->private_key));
    return KeyPair{/*x=*/public_key_bytes, /*y=*/"", private_key_bytes};
  }
  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(curve);
  if (!ec_key.ok()) {
    return ec_key.status();
  }
  return KeyPair{
      ec_key->pub_x,
      ec_key->pub_y,
      std::string(util::SecretDataAsStringView(ec_key->priv)),
  };
}

TEST_P(EciesProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = test_case.kem_params;
  *params.mutable_dem_params() = test_case.dem_params;
  params.set_ec_point_format(test_case.ec_point_format);

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_x(key_pair->x);
  key_proto.set_y(key_pair->y);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              Eq(test_case.id.has_value()));

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  absl::StatusOr<EciesParameters> expected_parameters =
      parameters_builder.Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<EciesPublicKey> expected_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    expected_key = EciesPublicKey::CreateForNistCurve(
        *expected_parameters,
        EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)), test_case.id,
        GetPartialKeyAccess());
  } else {
    expected_key = EciesPublicKey::CreateForCurveX25519(
        *expected_parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(EciesProtoSerializationTest, ParsePublicKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_x(key_pair->x);
  key_proto.set_y(key_pair->y);
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
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Only version 0 keys are accepted for EciesAeadHkdfPublicKey")));
}

TEST_P(EciesProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  absl::StatusOr<EciesParameters> parameters = parameters_builder.Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<EciesPublicKey> public_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    public_key = EciesPublicKey::CreateForNistCurve(
        *parameters, EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)),
        test_case.id, GetPartialKeyAccess());
  } else {
    public_key = EciesPublicKey::CreateForCurveX25519(
        *parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, /*token=*/absl::nullopt);
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
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  EciesAeadHkdfPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  const std::string prefix =
      (test_case.curve_type == EciesParameters::CurveType::kX25519)
          ? ""
          : std::string("\x00", 1);
  EXPECT_THAT(proto_key.x(), Eq(absl::StrCat(prefix, key_pair->x)));
  EXPECT_THAT(proto_key.y(), Eq(absl::StrCat(prefix, key_pair->y)));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().ec_point_format(),
              Eq(test_case.ec_point_format));

  ASSERT_THAT(proto_key.params().has_kem_params(), IsTrue());
  EXPECT_THAT(proto_key.params().kem_params().curve_type(),
              Eq(test_case.kem_params.curve_type()));
  EXPECT_THAT(proto_key.params().kem_params().hkdf_hash_type(),
              Eq(test_case.kem_params.hkdf_hash_type()));
  EXPECT_THAT(proto_key.params().kem_params().hkdf_salt(),
              Eq(test_case.kem_params.hkdf_salt()));

  ASSERT_THAT(proto_key.params().has_dem_params(), IsTrue());
  ASSERT_THAT(proto_key.params().dem_params().has_aead_dem(), IsTrue());
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().type_url(),
              Eq(test_case.dem_params.aead_dem().type_url()));
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().output_prefix_type(),
              Eq(test_case.dem_params.aead_dem().output_prefix_type()));
  EXPECT_THAT(proto_key.params().dem_params().aead_dem().value(),
              Eq(test_case.dem_params.aead_dem().value()));
}

TEST_P(EciesProtoSerializationTest, ParsePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() = test_case.kem_params;
  *params.mutable_dem_params() = test_case.dem_params;
  params.set_ec_point_format(test_case.ec_point_format);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(key_pair->x);
  public_key_proto.set_y(key_pair->y);
  *public_key_proto.mutable_params() = params;

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              Eq(test_case.id.has_value()));

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  absl::StatusOr<EciesParameters> expected_parameters =
      parameters_builder.Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<EciesPublicKey> expected_public_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    expected_public_key = EciesPublicKey::CreateForNistCurve(
        *expected_parameters,
        EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)), test_case.id,
        GetPartialKeyAccess());
  } else {
    expected_public_key = EciesPublicKey::CreateForCurveX25519(
        *expected_parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> expected_private_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    expected_private_key = EciesPrivateKey::CreateForNistCurve(
        *expected_public_key,
        RestrictedBigInteger(key_pair->private_key,
                             InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
  } else {
    expected_private_key = EciesPrivateKey::CreateForCurveX25519(
        *expected_public_key,
        RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
  }
  ASSERT_THAT(expected_private_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(EciesProtoSerializationTest, ParsePrivateKeyWithInvalidSerialization) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument, _));
}

TEST_F(EciesProtoSerializationTest, ParsePrivateKeyWithNoPublicKey) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_key_value(key_pair->private_key);

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(EciesProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(key_pair->x);
  public_key_proto.set_y(key_pair->y);
  *public_key_proto.mutable_params() = params;

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(key_pair->private_key);

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
  EXPECT_THAT(
      key.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Only version 0 keys are accepted for EciesAeadHkdfPrivateKey")));
}

TEST_F(EciesProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersion) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(1);
  public_key_proto.set_x(key_pair->x);
  public_key_proto.set_y(key_pair->y);
  *public_key_proto.mutable_params() = params;

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(key_pair->private_key);

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
                       HasSubstr("Only version 0 public keys are accepted for "
                                 "EciesAeadHkdfPrivateKey")));
}

TEST_F(EciesProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesAeadHkdfParams params;
  *params.mutable_kem_params() =
      CreateKemParams(EllipticCurveType::NIST_P256, HashType::SHA256, kSalt);
  *params.mutable_dem_params() = CreateAesGcmDemParams(16);
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(key_pair->x);
  public_key_proto.set_y(key_pair->y);
  *public_key_proto.mutable_params() = params;

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(key_pair->private_key);

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(EciesProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  EciesParameters::Builder parameters_builder =
      EciesParameters::Builder()
          .SetCurveType(test_case.curve_type)
          .SetHashType(test_case.hash_type)
          .SetDemId(test_case.dem_id)
          .SetVariant(test_case.variant);
  if (test_case.point_format.has_value()) {
    parameters_builder.SetNistCurvePointFormat(*test_case.point_format);
  }
  if (test_case.salt.has_value()) {
    parameters_builder.SetSalt(*test_case.salt);
  }
  absl::StatusOr<EciesParameters> parameters = parameters_builder.Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(test_case.kem_params.curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<EciesPublicKey> public_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    public_key = EciesPublicKey::CreateForNistCurve(
        *parameters, EcPoint(BigInteger(key_pair->x), BigInteger(key_pair->y)),
        test_case.id, GetPartialKeyAccess());
  } else {
    public_key = EciesPublicKey::CreateForCurveX25519(
        *parameters, key_pair->x, test_case.id, GetPartialKeyAccess());
  }
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key;
  if (test_case.curve_type != EciesParameters::CurveType::kX25519) {
    private_key = EciesPrivateKey::CreateForNistCurve(
        *public_key,
        RestrictedBigInteger(key_pair->private_key,
                             InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
  } else {
    private_key = EciesPrivateKey::CreateForCurveX25519(
        *public_key,
        RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
        GetPartialKeyAccess());
  }
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
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  EciesAeadHkdfPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  const std::string prefix =
      (test_case.curve_type == EciesParameters::CurveType::kX25519)
          ? ""
          : std::string("\x00", 1);
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(),
              Eq(absl::StrCat(prefix, key_pair->private_key)));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().x(),
              Eq(absl::StrCat(prefix, key_pair->x)));
  EXPECT_THAT(proto_key.public_key().y(),
              Eq(absl::StrCat(prefix, key_pair->y)));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());

  ASSERT_THAT(proto_key.public_key().params().has_kem_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().kem_params().curve_type(),
              Eq(test_case.kem_params.curve_type()));
  EXPECT_THAT(proto_key.public_key().params().kem_params().hkdf_hash_type(),
              Eq(test_case.kem_params.hkdf_hash_type()));
  EXPECT_THAT(proto_key.public_key().params().kem_params().hkdf_salt(),
              Eq(test_case.kem_params.hkdf_salt()));

  ASSERT_THAT(proto_key.public_key().params().has_dem_params(), IsTrue());
  ASSERT_THAT(proto_key.public_key().params().dem_params().has_aead_dem(),
              IsTrue());
  EXPECT_THAT(
      proto_key.public_key().params().dem_params().aead_dem().type_url(),
      Eq(test_case.dem_params.aead_dem().type_url()));
  EXPECT_THAT(proto_key.public_key()
                  .params()
                  .dem_params()
                  .aead_dem()
                  .output_prefix_type(),
              Eq(test_case.dem_params.aead_dem().output_prefix_type()));
  EXPECT_THAT(proto_key.public_key().params().dem_params().aead_dem().value(),
              Eq(test_case.dem_params.aead_dem().value()));
  EXPECT_THAT(proto_key.public_key().params().ec_point_format(),
              Eq(test_case.ec_point_format));
}

TEST_F(EciesProtoSerializationTest, SerializePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  absl::StatusOr<EciesParameters> parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kAes256SivRaw)
          .SetVariant(EciesParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(EllipticCurveType::CURVE25519));
  ASSERT_THAT(key_pair, IsOk());

  absl::StatusOr<EciesPublicKey> public_key =
      EciesPublicKey::CreateForCurveX25519(*parameters, key_pair->x,
                                           /*id_requirement=*/absl::nullopt,
                                           GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EciesPrivateKey> private_key =
      EciesPrivateKey::CreateForCurveX25519(
          *public_key,
          RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
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

// TODO: b/330508549 - Remove test after existing keys are updated/removed.
TEST(AeadDemTypeUrlExceptionTest, ParseWithInvalidUrl) {
  ASSERT_THAT(RegisterEciesProtoSerialization(), IsOk());

  const std::string invalid_aead_dem_type_url =
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305KeyFormat";
  XChaCha20Poly1305KeyFormat format;
  format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(invalid_aead_dem_type_url);
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  format.SerializeToString(key_template.mutable_value());
  EciesAeadDemParams dem_params;
  *dem_params.mutable_aead_dem() = key_template;

  EciesAeadHkdfParams params;
  *params.mutable_dem_params() = dem_params;
  *params.mutable_kem_params() = CreateKemParams(EllipticCurveType::CURVE25519,
                                                 HashType::SHA256, /*salt=*/"");
  params.set_ec_point_format(EcPointFormat::COMPRESSED);
  EciesAeadHkdfKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<KeyPair> key_pair = GenerateKeyPair(
      util::Enums::ProtoToSubtle(params.kem_params().curve_type()));
  ASSERT_THAT(key_pair, IsOk());

  EciesAeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(key_pair->x);
  public_key_proto.set_y(key_pair->y);
  *public_key_proto.mutable_params() = params;

  EciesAeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(key_pair->private_key);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> private_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<EciesParameters> expected_parameters =
      EciesParameters::Builder()
          .SetCurveType(EciesParameters::CurveType::kX25519)
          .SetHashType(EciesParameters::HashType::kSha256)
          .SetDemId(EciesParameters::DemId::kXChaCha20Poly1305Raw)
          .SetVariant(EciesParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT((*private_key)->GetParameters(), Eq(*expected_parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
