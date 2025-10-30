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

#include "tink/jwt/jwt_rsa_ssa_pss_private_key.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_rsa_ssa_pss_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pss_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPssParameters::Algorithm algorithm;
  JwtRsaSsaPssParameters::KidStrategy kid_strategy;
  absl::optional<int> id_requirement;
  absl::optional<std::string> custom_kid;
  absl::optional<std::string> expected_kid;
};

struct PrivateValues {
  RestrictedBigInteger p;
  RestrictedBigInteger q;
  RestrictedBigInteger dp;
  RestrictedBigInteger dq;
  RestrictedBigInteger d;
  RestrictedBigInteger q_inv;
};

constexpr int kModulusSizeInBits = 2048;

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

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  ABSL_CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
}

PrivateValues GetValidPrivateValues() {
  return PrivateValues{
      /*p=*/RestrictedBigInteger(Base64WebSafeDecode(kP),
                                 InsecureSecretKeyAccess::Get()),
      /*q=*/
      RestrictedBigInteger(Base64WebSafeDecode(kQ),
                           InsecureSecretKeyAccess::Get()),
      /*dp=*/
      RestrictedBigInteger(Base64WebSafeDecode(kDp),
                           InsecureSecretKeyAccess::Get()),
      /*dq=*/
      RestrictedBigInteger(Base64WebSafeDecode(kDq),
                           InsecureSecretKeyAccess::Get()),
      /*d=*/
      RestrictedBigInteger(Base64WebSafeDecode(kD),
                           InsecureSecretKeyAccess::Get()),
      /*q_inv=*/
      RestrictedBigInteger(Base64WebSafeDecode(kQInv),
                           InsecureSecretKeyAccess::Get())};
}

JwtRsaSsaPssPublicKey GetValidPublicKey(
    JwtRsaSsaPssParameters::Algorithm algorithm,
    JwtRsaSsaPssParameters::KidStrategy kid_strategy,
    absl::optional<int> id_requirement,
    absl::optional<std::string> custom_kid) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(algorithm)
          .SetKidStrategy(kid_strategy)
          .Build();
  ABSL_CHECK_OK(parameters.status()) << "Failed to create parameters.";

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  JwtRsaSsaPssPublicKey::Builder builder = JwtRsaSsaPssPublicKey::Builder()
                                               .SetParameters(*parameters)
                                               .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    builder.SetCustomKid(*custom_kid);
  }

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string FlipFirstByte(absl::string_view str) {
  std::string res(str);
  res[0] = ~res[0];
  return res;
}

using JwtRsaSsaPssPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPssPrivateKeyTestSuite, JwtRsaSsaPssPrivateKeyTest,
    Values(TestCase{JwtRsaSsaPssParameters::Algorithm::kPs256,
                    JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId,
                    /*id_requirement=*/0x1ac6a944,
                    /*custom_kid=*/absl::nullopt, /*expected_kid=*/"GsapRA"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs384,
                    JwtRsaSsaPssParameters::KidStrategy::kCustom,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/"custom_kid", /*expected_kid=*/"custom_kid"},
           TestCase{JwtRsaSsaPssParameters::Algorithm::kPs512,
                    JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/absl::nullopt,
                    /*expected_kid=*/absl::nullopt}));

TEST_P(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  JwtRsaSsaPssPublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentP(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQ(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficient(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponent(), Eq(private_values.d));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyFromBoringSslWorks) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  ASSERT_THAT(rsa, NotNull());

  // Set public exponent to 65537.
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  ASSERT_THAT(RSA_generate_key_ex(rsa.get(), 2048, e.get(), /*cb=*/nullptr),
              Eq(1));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  absl::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  ASSERT_THAT(n_str, IsOk());
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  ASSERT_THAT(e_str, IsOk());
  absl::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  ASSERT_THAT(d_str, IsOk());
  absl::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(p_str, IsOk());
  absl::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  ASSERT_THAT(q_str, IsOk());
  absl::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  ASSERT_THAT(dp_str, IsOk());
  absl::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  ASSERT_THAT(dq_str, IsOk());
  absl::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  ASSERT_THAT(q_inv_str, IsOk());

  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(*e_str))
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(*n_str))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(
              RestrictedBigInteger(*p_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(
              RestrictedBigInteger(*q_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedBigInteger(*dp_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedBigInteger(*dq_str, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedBigInteger(*d_str, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedBigInteger(*q_inv_str, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*p_str));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*q_str));
  EXPECT_THAT(private_key->GetPrimeExponentP().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dp_str));
  EXPECT_THAT(private_key->GetPrimeExponentQ().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dq_str));
  EXPECT_THAT(private_key->GetCrtCoefficient().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*q_inv_str));
  EXPECT_THAT(private_key->GetPrivateExponent().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*d_str));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(private_key->GetKid(), Eq(absl::nullopt));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  JwtRsaSsaPssPublicKey valid_public_key =
      GetValidPublicKey(JwtRsaSsaPssParameters::Algorithm::kPs256,
                        JwtRsaSsaPssParameters::KidStrategy::kIgnored,
                        /*id_requirement=*/absl::nullopt,
                        /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key_modified_modulus =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(valid_public_key.GetParameters())
          .SetModulus(BigInteger(
              FlipFirstByte(Base64WebSafeDecode(k2048BitRsaModulus))))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_modulus =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key_modified_modulus)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_modulus.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Modulus size is")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /* id_requirement= */ absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_prime_p =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kP)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_prime_q =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kQ)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_prime_exponent_p =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kDp)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_prime_exponent_q =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kDq)),
                                   InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_private_exponent =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kD)),
                                   InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_private_exponent.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_modified_crt_coefficient =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(
              RestrictedBigInteger(FlipFirstByte(Base64WebSafeDecode(kQInv)),
                                   InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_crt_coefficient.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_public_key_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_public_key_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting the public key")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrimePNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_prime_p_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_prime_p_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting both prime factors")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrimeQNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_prime_q_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_prime_q_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting both prime factors")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_prime_exponent_p_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_prime_exponent_p_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting both prime exponents")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_prime_exponent_q_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_prime_exponent_q_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting both prime exponents")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildPrivateExponentNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_private_exponent_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_private_exponent_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting the private exponent")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  JwtRsaSsaPssPublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key_no_crt_coefficient_set =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(
      private_key_no_crt_coefficient_set.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot build without setting the CRT coefficient")));
}

TEST(JwtRsaSsaPssPrivateKeyTest, CreateMismatchedKeyPairFails) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(JwtRsaSsaPssParameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Test value from
  // https://github.com/google/wycheproof/blob/master/testvectors/rsa_pkcs1_2048_test.json
  BigInteger mismatched_modulus(Base64WebSafeDecode(
      "3ZBFkDl4CMQxQyliPZATRThDJRsTuLPE_vVFmBEq8-sxxxEDxiWZUWdOU72Tp-NtGUcuR06-"
      "gChobZUpSE2Lr-pKBLoZVVZnYWyEeGcFlACcm8aj7-UidMumTHJHR9ftwZTk_"
      "t3jKjKJ2Uwxk25-"
      "ehXXVvVISS9bNFuSfoxhi91VCsshoXrhSDBDg9ubPHuqPkyL2OhEqITao-GNVpmMsy-"
      "brk1B1WoY3dQxPICJt16du5EoRwusmwh_thkoqw-"
      "MTIk2CwIImQCNCOi9MfkHqAfoBWrWgA3_357Z2WSpOefkgRS4SXhVGsuFyd-"
      "RlvPv9VKG1s1LOagiqKd2Ohggjw"));
  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(mismatched_modulus)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key.status(),
              StatusIs(absl::StatusCode ::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST_P(JwtRsaSsaPssPrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  JwtRsaSsaPssPublicKey valid_public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> same_private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(same_private_key, IsOk());

  EXPECT_TRUE(*private_key == *same_private_key);
  EXPECT_TRUE(*same_private_key == *private_key);
  EXPECT_FALSE(*private_key != *same_private_key);
  EXPECT_FALSE(*same_private_key != *private_key);
}

TEST(JwtRsaSsaPssPrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<JwtRsaSsaPssParameters> parameters =
      JwtRsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPssParameters::Algorithm::kPs256)
          .SetKidStrategy(
              JwtRsaSsaPssParameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key1 =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<JwtRsaSsaPssPublicKey> public_key2 =
      JwtRsaSsaPssPublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key1 =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key2 =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key2)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST(JwtRsaSsaPssPrivateKeyTest, DifferentKeyTypesNotEqual) {
  JwtRsaSsaPssPublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != public_key);
  EXPECT_TRUE(public_key != *private_key);
  EXPECT_FALSE(*private_key == public_key);
  EXPECT_FALSE(public_key == *private_key);
}

TEST(JwtRsaSsaPssPrivateKeyTest, Clone) {
  JwtRsaSsaPssPublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPssParameters::Algorithm::kPs256,
      JwtRsaSsaPssParameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPssPrivateKey> private_key =
      JwtRsaSsaPssPrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
