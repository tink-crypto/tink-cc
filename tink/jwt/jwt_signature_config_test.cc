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
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "tink/internal/tink_proto_structs.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "proto/jwt_ecdsa.pb.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
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

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(JwtEs256Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtEcdsaParameters> parameters =
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

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
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

  absl::StatusOr<internal::EcKey> ec_key =
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

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
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

// Test vector from https://www.rfc-editor.org/rfc/rfc7517#appendix-C.1
constexpr absl::string_view k2048BitRsaModulus =
    "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-"
    "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_"
    "LYywlAGZ21WSdS_"
    "PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
    "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_"
    "aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q";

constexpr absl::string_view kD =
    "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_"
    "jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_"
    "IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_"
    "PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqADC6p1M3h33t"
    "surY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWmeRDkK2ahecG85-"
    "oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ";

constexpr absl::string_view kP =
    "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-WE-"
    "ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-"
    "M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws";

constexpr absl::string_view kQ =
    "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_"
    "coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_"
    "ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s";

constexpr absl::string_view kDp =
    "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_"
    "MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_"
    "lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c";

constexpr absl::string_view kDq =
    "AvfS0-"
    "gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN06H7CFtr"
    "kxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEA"
    "u_lRFCOJ3xDea-ots";

constexpr absl::string_view kQInv =
    "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ57_"
    "bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-"
    "2lNx_76aBZoOUu9HCJ-UsfSOI8";

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  ABSL_CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

TEST_F(JwtSignatureConfigTest,
       JwtRsaSSaPkcs1ProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              JwtRs256_2048_F4_Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
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

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
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

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(Base64WebSafeDecode(k2048BitRsaModulus)))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(Base64WebSafeDecode(kP),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(Base64WebSafeDecode(kQ),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(Base64WebSafeDecode(kDp),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(Base64WebSafeDecode(kDq),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(Base64WebSafeDecode(kD),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(Base64WebSafeDecode(kQInv),
                                            InsecureSecretKeyAccess::Get()))
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

TEST_F(JwtSignatureConfigTest, JwtRsaSsaPssProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              JwtPs256_2048_F4_Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
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
       JwtRsaSsaPssProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(Base64WebSafeDecode(k2048BitRsaModulus));
  public_key_proto.set_e(kF4Str);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
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
       JwtRsaSsaPssProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  google::crypto::tink::JwtRsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtRsaSsaPssAlgorithm::PS256);
  public_key_proto.set_n(Base64WebSafeDecode(k2048BitRsaModulus));
  public_key_proto.set_e(kF4Str);

  google::crypto::tink::JwtRsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(Base64WebSafeDecode(kP));
  private_key_proto.set_q(Base64WebSafeDecode(kQ));
  private_key_proto.set_dp(Base64WebSafeDecode(kDp));
  private_key_proto.set_dq(Base64WebSafeDecode(kDq));
  private_key_proto.set_d(Base64WebSafeDecode(kD));
  private_key_proto.set_crt(Base64WebSafeDecode(kQInv));

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(Base64WebSafeDecode(k2048BitRsaModulus)))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(Base64WebSafeDecode(kP),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(Base64WebSafeDecode(kQ),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(Base64WebSafeDecode(kDp),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(Base64WebSafeDecode(kDq),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(Base64WebSafeDecode(kD),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(Base64WebSafeDecode(kQInv),
                                            InsecureSecretKeyAccess::Get()))
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
