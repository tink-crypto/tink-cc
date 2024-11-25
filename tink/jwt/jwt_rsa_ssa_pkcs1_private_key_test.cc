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

#include "tink/jwt/jwt_rsa_ssa_pkcs1_private_key.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key.h"
#include "tink/util/test_util.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_parameters.h"
#include "tink/jwt/jwt_rsa_ssa_pkcs1_public_key.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/util/statusor.h"
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
  JwtRsaSsaPkcs1Parameters::Algorithm algorithm;
  JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy;
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

// Test vector from https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
constexpr absl::string_view k2048BitRsaModulus =
    "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-"
    "4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_"
    "YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-"
    "bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-"
    "UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_"
    "I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_"
    "h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";

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
    "7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3"
    "Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_"
    "pbLBSp3nssTdlqvd0tIiTHU";

constexpr absl::string_view kQInv =
    "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-"
    "DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_"
    "QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-"
    "ZQwVK0JKSHuLFkuQ3U";

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
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

JwtRsaSsaPkcs1PublicKey GetValidPublicKey(
    JwtRsaSsaPkcs1Parameters::Algorithm algorithm,
    JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy,
    absl::optional<int> id_requirement,
    absl::optional<std::string> custom_kid) {
  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(algorithm)
          .SetKidStrategy(kid_strategy)
          .Build();
  CHECK_OK(parameters.status()) << "Failed to create parameters.";

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  JwtRsaSsaPkcs1PublicKey::Builder builder = JwtRsaSsaPkcs1PublicKey::Builder()
                                                 .SetParameters(*parameters)
                                                 .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    builder.SetCustomKid(*custom_kid);
  }

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string FlipFirstByte(absl::string_view str) {
  std::string res(str);
  res[0] = ~res[0];
  return res;
}

using JwtRsaSsaPkcs1PrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    JwtRsaSsaPkcs1PrivateKeyTestSuite, JwtRsaSsaPkcs1PrivateKeyTest,
    Values(TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
                    /*id_requirement=*/0x1ac6a944,
                    /*custom_kid=*/absl::nullopt, /*expected_kid=*/"GsapRA"},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs384,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/"custom_kid", /*expected_kid=*/"custom_kid"},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs512,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                    /*id_requirement=*/absl::nullopt,
                    /*custom_kid=*/absl::nullopt,
                    /*expected_kid=*/absl::nullopt}));

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  JwtRsaSsaPkcs1PublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyFromBoringSslWorks) {
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

  util::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  ASSERT_THAT(n_str, IsOk());
  util::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  ASSERT_THAT(e_str, IsOk());
  util::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  ASSERT_THAT(d_str, IsOk());
  util::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(p_str, IsOk());
  util::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  ASSERT_THAT(q_str, IsOk());
  util::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  ASSERT_THAT(dp_str, IsOk());
  util::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  ASSERT_THAT(dq_str, IsOk());
  util::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  ASSERT_THAT(q_inv_str, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(*e_str))
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(*n_str))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  JwtRsaSsaPkcs1PublicKey valid_public_key =
      GetValidPublicKey(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                        JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                        /*id_requirement=*/absl::nullopt,
                        /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key_modified_modulus =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(valid_public_key.GetParameters())
          .SetModulus(BigInteger(
              FlipFirstByte(Base64WebSafeDecode(k2048BitRsaModulus))))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_modulus =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /* id_requirement= */ absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_prime_p =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_prime_q =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_prime_exponent_p =
          JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_prime_exponent_q =
          JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_private_exponent =
          JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_crt_coefficient =
          JwtRsaSsaPkcs1PrivateKey::Builder()
              .SetPublicKey(valid_public_key)
              .SetPrimeP(private_values.p)
              .SetPrimeQ(private_values.q)
              .SetPrimeExponentP(private_values.dp)
              .SetPrimeExponentQ(private_values.dq)
              .SetPrivateExponent(private_values.d)
              .SetCrtCoefficient(RestrictedBigInteger(
                  FlipFirstByte(Base64WebSafeDecode(kQInv)),
                  InsecureSecretKeyAccess::Get()))
              .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_crt_coefficient.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("RSA key pair is not valid")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_public_key_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimePNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_p_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeQNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_q_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_p_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_q_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateExponentNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_private_exponent_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_crt_coefficient_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, CreateMismatchedKeyPairFails) {
  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
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
  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(mismatched_modulus)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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
                       HasSubstr("RSA key pair is not valid")));
}

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  JwtRsaSsaPkcs1PublicKey valid_public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> same_private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(Base64WebSafeDecode(k2048BitRsaModulus));
  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key1 =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key2 =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key1 =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key1)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key1, IsOk());

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key2 =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, DifferentKeyTypesNotEqual) {
  JwtRsaSsaPkcs1PublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, Clone) {
  JwtRsaSsaPkcs1PublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/absl::nullopt, /*custom_kid=*/absl::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  util::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
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
