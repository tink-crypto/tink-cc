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

#include "tink/hybrid/hpke_proto_serialization.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#else
#include "openssl/ec.h"
#endif
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/testing/equals_proto_key_serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_matchers.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::internal::ProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::EqualsProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
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

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.5
std::string P256PointAsString() {
  std::string pub_key_x_p256_hex =
      "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
  std::string pub_key_y_p256_hex =
      "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p256_hex, pub_key_y_p256_hex));
}

RestrictedData P256SecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.6
std::string P384PointAsString() {
  std::string pub_key_x_p384_hex =
      "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA"
      "9055866064A254515480BC13";
  std::string pub_key_y_p384_hex =
      "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C"
      "3AE0D4FE7344FD2533264720";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p384_hex, pub_key_y_p384_hex));
}

RestrictedData P384SecretValue() {
  SecretData secret_data = SecretDataFromStringView(
      HexDecodeOrDie("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA477407"
                     "87137D896D5724E4C70A825F872C9EA60D2EDF5"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

// Taken from https://datatracker.ietf.org/doc/html/rfc6979.html#appendix-A.2.7
std::string P521PointAsString() {
  std::string pub_key_x_p521_hex =
      "01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D4"
      "6E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4";
  std::string pub_key_y_p521_hex =
      "00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25"
      "741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5";
  return HexDecodeOrDie(
      absl::StrCat("04", pub_key_x_p521_hex, pub_key_y_p521_hex));
}

RestrictedData P521SecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB"
      "32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

// Taken from Java, HpkeTestUtil
std::string X25519PublicValue() {
  return HexDecodeOrDie(
      "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
}

RestrictedData X25519SecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

// Taken from
// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-09.html
std::string XWingPublicValue() {
  return HexDecodeOrDie(
      "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5b19cfc3d"
      "a5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34244e66969cf15b3b"
      "2a785329f61b096b277ea037383479a6b556de7231fe4b7fa9c9ac24c0699a0018a52534"
      "01bacfa905ca816573e56a2d2e067e9b7287533ba13a937dedb31fa44baced4076992361"
      "0034ae31e619a170245199b3c5c39864859fe1b4c9717a07c30495bdfb98a0a002ccf56c"
      "1286cef5041dede3c44cf16bf562c7448518026b3d8b9940680abd38a1575fd27b58da06"
      "3bfac32c39c30869374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2ae"
      "a10463111c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e"
      "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7bad4da40"
      "b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d8392b3e131e9a70c"
      "1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2808caafd516cd25052c5c362"
      "543c2517e4acd0e60ec07163009b6425fc32277acee71c24bab53ed9f29e74c66a0a3564"
      "955998d76b96a9a8b50d1635a4d7a67eb42df5644d330457293a8042f53cc7a69288f17e"
      "d55827e82b28e82665a86a14fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af"
      "829068f1358963cb333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519"
      "317714cb4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4"
      "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525860f58be"
      "3be61c964604a6ac814e6935596402a520a4670b3d284318866593d15a4bb01c35e3e587"
      "ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bcf6038ccbe33fbcf51a54a584"
      "fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8aad4ad64e5c42bb8877c0ebec2b5e387c"
      "8a988fdc23beb9e16c8757781e0a1499c61e138c21f216c29d076979871caa6942bafc09"
      "0544bee99b54b16cb9a9a364d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c95"
      "2151a91b7a10772429dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae406"
      "5ed34d73d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5"
      "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c6f7e3173"
      "46e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692ab8e1bbb12839573"
      "cce19df183b45835bbb55052f9fc66a1678ef2a36dea78411e6c8d60501b4e60592d1369"
      "8a943b509185db912e2ea10be06171236b327c71716094c964a68b03377f513a05bcd99c"
      "1f346583bb052977a10a12adfc758034e5617da4c1276585e5774e1f3b9978b09d0e9c44"
      "d3bc86151c43aad185712717340223ac381d21150a04294e97bb13bbda21b5a182b6da96"
      "9e19a7fd072737fa8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611"
      "d0c7a7da104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734"
      "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69859edb06"
      "eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534");
}

RestrictedData XWingSecretValue() {
  SecretData secret_data = SecretDataFromStringView(HexDecodeOrDie(
      "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"));
  return RestrictedData(secret_data, InsecureSecretKeyAccess::Get());
}

struct TestCase {
  HpkeParameters::Variant variant;
  HpkeParameters::KemId kem_id;
  HpkeParameters::KdfId kdf_id;
  HpkeParameters::AeadId aead_id;
  OutputPrefixTypeEnum output_prefix_type;
  HpkeKem kem;
  HpkeKdf kdf;
  HpkeAead aead;
  absl::optional<int> id;
  std::string output_prefix;
  subtle::EllipticCurveType curve;
};

class HpkeProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(HpkeProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    HpkeProtoSerializationTestSuite, HpkeProtoSerializationTest,
    Values(TestCase{HpkeParameters::Variant::kTink,
                    HpkeParameters::KemId::kDhkemP256HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kAesGcm128,
                    OutputPrefixTypeEnum::kTink,
                    HpkeKem::DHKEM_P256_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                    HpkeAead::AES_128_GCM, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5),
                    subtle::EllipticCurveType::NIST_P256},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP384HkdfSha384,
                    HpkeParameters::KdfId::kHkdfSha384,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixTypeEnum::kCrunchy,
                    HpkeKem::DHKEM_P384_HKDF_SHA384, HpkeKdf::HKDF_SHA384,
                    HpkeAead::AES_256_GCM,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5),
                    subtle::EllipticCurveType::NIST_P384},
           TestCase{HpkeParameters::Variant::kCrunchy,
                    HpkeParameters::KemId::kDhkemP521HkdfSha512,
                    HpkeParameters::KdfId::kHkdfSha512,
                    HpkeParameters::AeadId::kAesGcm256,
                    OutputPrefixTypeEnum::kCrunchy,
                    HpkeKem::DHKEM_P521_HKDF_SHA512, HpkeKdf::HKDF_SHA512,
                    HpkeAead::AES_256_GCM,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5),
                    subtle::EllipticCurveType::NIST_P521},
           TestCase{HpkeParameters::Variant::kNoPrefix,
                    HpkeParameters::KemId::kDhkemX25519HkdfSha256,
                    HpkeParameters::KdfId::kHkdfSha256,
                    HpkeParameters::AeadId::kChaCha20Poly1305,
                    OutputPrefixTypeEnum::kRaw,
                    HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                    HpkeAead::CHACHA20_POLY1305,
                    /*id=*/absl::nullopt, /*output_prefix=*/"",
                    subtle::EllipticCurveType::CURVE25519}));

TEST_P(HpkeProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(test_case.kem);
  params.set_kdf(test_case.kdf);
  params.set_aead(test_case.aead);
  HpkeKeyFormat key_format_proto;
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

  const HpkeParameters* hpke_parameters =
      dynamic_cast<const HpkeParameters*>(parameters->get());
  ASSERT_THAT(hpke_parameters, NotNull());
  EXPECT_THAT(hpke_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(hpke_parameters->GetKemId(), Eq(test_case.kem_id));
  EXPECT_THAT(hpke_parameters->GetKdfId(), Eq(test_case.kdf_id));
  EXPECT_THAT(hpke_parameters->GetAeadId(), Eq(test_case.aead_id));
}

TEST_F(HpkeProtoSerializationTest, ParseLegacyAsCrunchy) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
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
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKem) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::KEM_UNKNOWN);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
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

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownKdf) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::KDF_UNKNOWN);
  params.set_aead(HpkeAead::CHACHA20_POLY1305);
  HpkeKeyFormat key_format_proto;
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

TEST_F(HpkeProtoSerializationTest, ParseParametersWithUnkownAead) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  HpkeParams params;
  params.set_kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
  params.set_kdf(HpkeKdf::HKDF_SHA256);
  params.set_aead(HpkeAead::AEAD_UNKNOWN);
  HpkeKeyFormat key_format_proto;
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

TEST_P(HpkeProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  absl::StatusOr<HpkeParameters> parameters = HpkeParameters::Builder()
                                                  .SetVariant(test_case.variant)
                                                  .SetKemId(test_case.kem_id)
                                                  .SetKdfId(test_case.kdf_id)
                                                  .SetAeadId(test_case.aead_id)
                                                  .Build();
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
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type,
              Eq(test_case.output_prefix_type));

  HpkeKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
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
    absl::StatusOr<std::unique_ptr<internal::X25519Key>> x25519_key =
        internal::NewX25519Key();
    if (!x25519_key.ok()) {
      return x25519_key.status();
    }
    return KeyPair{
        std::string(reinterpret_cast<const char*>((*x25519_key)->public_value),
                    internal::X25519KeyPubKeySize()),
        std::string(util::SecretDataAsStringView((*x25519_key)->private_key))};
  }
  absl::StatusOr<internal::EcKey> ec_key = internal::NewEcKey(curve);
  if (!ec_key.ok()) {
    return ec_key.status();
  }
  absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
      internal::GetEcPoint(curve, ec_key->pub_x, ec_key->pub_y);
  if (!ec_point.ok()) {
    return ec_point.status();
  }
  absl::StatusOr<std::string> pub = internal::EcPointEncode(
      curve, subtle::EcPointFormat::UNCOMPRESSED, ec_point->get());
  if (!pub.ok()) {
    return pub.status();
  }
  return KeyPair{*pub, std::string(util::SecretDataAsStringView(ec_key->priv))};
}

TEST_P(HpkeProtoSerializationTest, ParsePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePublicKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(HpkeProtoSerializationTest, SerializePublicKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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

TEST_P(HpkeProtoSerializationTest, ParsePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithNoPublicKey) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

  absl::StatusOr<KeyPair> key_pair =
      GenerateKeyPair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::HpkePrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_private_key(key_pair->private_key);

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

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidVersion) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Only version 0 keys are accepted.")));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyWithInvalidPublicKeyVersion) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Only version 0 public keys are accepted.")));
}

TEST_F(HpkeProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccess) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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

TEST_P(HpkeProtoSerializationTest, SerializePrivateKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());

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
      *parameters, key_pair->public_key, /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key,
      RestrictedData(key_pair->private_key, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
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
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(*test_key.key,
                                               InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization.status(), IsOk());
  ProtoKeySerialization* proto_serialization =
      dynamic_cast<ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, Not(IsNull()));
  EXPECT_THAT(*proto_serialization,
              EqualsProtoKeySerialization(test_key.proto_key_serialization));
}

TEST_P(ParseTest, ParserCorrectly) {
  ASSERT_THAT(RegisterHpkeProtoSerialization(), IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P384PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P384SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P521PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P521SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, X25519PublicValue(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, X25519SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, XWingPublicValue(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, XWingSecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      /*id_requirement=*/absl::nullopt);

  return KeyAndSerialization("PrivateKeyXWing",
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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
      0x12341234);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kCrunchy,
      0x12341234);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P384PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P384_HKDF_SHA384),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA384),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_256_GCM)}),
       FieldWithNumber(3).IsString(P384PointAsString())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P521PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P521_HKDF_SHA512),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA512),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P521PointAsString())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, X25519PublicValue(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_X25519_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA384),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_256_GCM)}),
       FieldWithNumber(3).IsString(X25519PublicValue())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, XWingPublicValue(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(google::crypto::tink::X_WING),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(XWingPublicValue())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      /*id_requirement=*/absl::nullopt);

  return KeyAndSerialization("PublicKeyXWing",
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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
      0x12341234);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/0x12341234,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());

  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.HpkePublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(
                google::crypto::tink::DHKEM_P256_HKDF_SHA256),
            FieldWithNumber(2).IsVarint(::google::crypto::tink::HKDF_SHA256),
            FieldWithNumber(3).IsVarint(::google::crypto::tink::AES_128_GCM)}),
       FieldWithNumber(3).IsString(P256PointAsString())},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kCrunchy,
      0x12341234);

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
  CHECK_OK(parameters.status());
  absl::StatusOr<HpkePublicKey> public_key = HpkePublicKey::Create(
      *parameters, P256PointAsString(), /*id_requirement=*/absl::nullopt,
      GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  absl::StatusOr<HpkePrivateKey> private_key = HpkePrivateKey::Create(
      *public_key, P256SecretValue(), GetPartialKeyAccess());
  CHECK_OK(private_key.status());

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
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

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
        PrivateKeyAndSerializationTink(), PrivateKeyAndSerializationCrunchy(),
        PublicKeyAndSerializationNistP256(),
        PublicKeyAndSerializationNistP384(),
        PublicKeyAndSerializationNistP521(), PublicKeyAndSerializationX25519(),
        PublicKeyAndSerializationXWing(), PublicKeyAndSerializationTink(),
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
                                         PrivateKeyAndSerializationTink(),
                                         PrivateKeyAndSerializationCrunchy(),
                                         PublicKeyAndSerializationNistP256(),
                                         PublicKeyAndSerializationNistP384(),
                                         PublicKeyAndSerializationNistP521(),
                                         PublicKeyAndSerializationXWing(),
                                         PublicKeyAndSerializationX25519(),
                                         PublicKeyAndSerializationTink(),
                                         PublicKeyAndSerializationCrunchy()));

}  // namespace
}  // namespace tink
}  // namespace crypto
