// Copyright 2023 Google Inc.
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

#include "tink/jwt/jwt_signature_config.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/config/global_registry.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Not;

class JwtSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtSignatureConfigTest, FailIfAndOnlyIfInInvalidFipsState) {
  // If FIPS is enabled, then we need FIPS also to be enabled in BoringSSL.
  // Otherwise we are in an invalid state and must fail.
  bool invalid_fips_state =
      internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl();

  if (invalid_fips_state) {
    EXPECT_THAT(JwtSignatureRegister(), Not(IsOk()));

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
  } else {
    EXPECT_THAT(JwtSignatureRegister(), IsOk());

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
  }
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(JwtEs256Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537

// RSA 2048-bits modulus value taken from
// https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
constexpr absl::string_view k2048BitRsaModulus =
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-"
    "4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_"
    "YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-"
    "bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-"
    "UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_"
    "I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_"
    "h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

TEST_F(JwtSignatureConfigTest,
       JwtRsaSSaPkcs1ProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              JwtRs256_2048_F4_Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(JwtSignatureConfigTest,
       JwtRsaSsaPkcs1ProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(Base64WebSafeDecode(k2048BitRsaModulus));
  public_key_proto.set_e(kF4Str);

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(Base64WebSafeDecode(k2048BitRsaModulus)))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

TEST_F(JwtSignatureConfigTest,
       JwtRsaSsaPkcs1ProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Test vector from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
  constexpr absl::string_view kD =
      "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_"
      "GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-"
      "GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_"
      "V51gfpRLI9JYanrC4D4qAdGcopV_"
      "0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_"
      "jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";

  constexpr absl::string_view kP =
      "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_"
      "5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_"
      "Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-"
      "KDV5z-y2XDwGUc";

  constexpr absl::string_view kQ =
      "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-"
      "7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_"
      "YwD66t62wDmpe_HlB-TnBA-"
      "njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";

  constexpr absl::string_view kDp =
      "BwKfV3Akq5_MFZDFZCnW-wzl-"
      "CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-"
      "FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_"
      "YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0";

  constexpr absl::string_view kDq =
      "h_96-mK1R_"
      "7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6"
      "N3"
      "Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_"
      "pbLBSp3nssTdlqvd0tIiTHU";

  constexpr absl::string_view kQInv =
      "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-"
      "DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_"
      "QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_"
      "gh6A5603k2-"
      "ZQwVK0JKSHuLFkuQ3U";

  google::crypto::tink::JwtRsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPkcs1Algorithm::RS256);
  public_key_proto.set_n(Base64WebSafeDecode(k2048BitRsaModulus));
  public_key_proto.set_e(kF4Str);

  google::crypto::tink::JwtRsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(Base64WebSafeDecode(kP));
  private_key_proto.set_q(Base64WebSafeDecode(kQ));
  private_key_proto.set_dp(Base64WebSafeDecode(kDp));
  private_key_proto.set_dq(Base64WebSafeDecode(kDq));
  private_key_proto.set_d(Base64WebSafeDecode(kD));
  private_key_proto.set_crt(Base64WebSafeDecode(kQInv));

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(Base64WebSafeDecode(k2048BitRsaModulus)))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(Base64WebSafeDecode(kP),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(Base64WebSafeDecode(kQ),
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              Base64WebSafeDecode(kDp), InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              Base64WebSafeDecode(kDq), InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              Base64WebSafeDecode(kD), InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              Base64WebSafeDecode(kQInv), InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
