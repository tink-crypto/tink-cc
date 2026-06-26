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
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"
#include "tink/key.h"
#include "tink/restricted_data.h"
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
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::NotNull;
using ::testing::StrEq;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  JwtRsaSsaPkcs1Parameters::Algorithm algorithm;
  JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy;
  std::optional<int> id_requirement;
  std::optional<std::string> custom_kid;
  std::optional<std::string> expected_kid;
};

struct PrivateValues {
  RestrictedData p;
  RestrictedData q;
  RestrictedData dp;
  RestrictedData dq;
  RestrictedData d;
  RestrictedData q_inv;
};

constexpr int kModulusSizeInBits = 2048;

const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));  // 65537

PrivateValues GetValidPrivateValues() {
  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();
  return PrivateValues{
      /*p=*/RestrictedData(vector.p, InsecureSecretKeyAccess::Get()),
      /*q=*/RestrictedData(vector.q, InsecureSecretKeyAccess::Get()),
      /*dp=*/RestrictedData(vector.dp, InsecureSecretKeyAccess::Get()),
      /*dq=*/RestrictedData(vector.dq, InsecureSecretKeyAccess::Get()),
      /*d=*/RestrictedData(vector.d, InsecureSecretKeyAccess::Get()),
      /*q_inv=*/RestrictedData(vector.q_inv, InsecureSecretKeyAccess::Get())};
}

JwtRsaSsaPkcs1PublicKey GetValidPublicKey(
    JwtRsaSsaPkcs1Parameters::Algorithm algorithm,
    JwtRsaSsaPkcs1Parameters::KidStrategy kid_strategy,
    std::optional<int> id_requirement, std::optional<std::string> custom_kid) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(algorithm)
          .SetKidStrategy(kid_strategy)
          .Build();
  ABSL_CHECK_OK(parameters.status()) << "Failed to create parameters.";

  BigInteger modulus(jwt_internal::GetRsa2048BitVector2().n);
  JwtRsaSsaPkcs1PublicKey::Builder builder = JwtRsaSsaPkcs1PublicKey::Builder()
                                                 .SetParameters(*parameters)
                                                 .SetModulus(modulus);
  if (id_requirement.has_value()) {
    builder.SetIdRequirement(*id_requirement);
  }
  if (custom_kid.has_value()) {
    builder.SetCustomKid(*custom_kid);
  }

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      builder.Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string Base64WebSafeDecode(absl::string_view base64_string) {
  std::string dest;
  ABSL_CHECK(absl::WebSafeBase64Unescape(base64_string, &dest))
      << "Failed to base64 decode.";

  return dest;
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
                    /*custom_kid=*/std::nullopt, /*expected_kid=*/"GsapRA"},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs384,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kCustom,
                    /*id_requirement=*/std::nullopt,
                    /*custom_kid=*/"custom_kid", /*expected_kid=*/"custom_kid"},
           TestCase{JwtRsaSsaPkcs1Parameters::Algorithm::kRs512,
                    JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                    /*id_requirement=*/std::nullopt,
                    /*custom_kid=*/std::nullopt,
                    /*expected_kid=*/std::nullopt}));

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  JwtRsaSsaPkcs1PublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
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
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
}

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest,
       BuildPrivateKeyAllowNonConstantTimeSucceeds) {
  TestCase test_case = GetParam();

  JwtRsaSsaPkcs1PublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .BuildAllowNonConstantTime(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest,
     BuildPrivateKeyAllowNonConstantTimeSucceedsWithLeadingBytes) {
  JwtRsaSsaPkcs1PublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
      /*id_requirement=*/0x1ac6a944, /*custom_kid=*/std::nullopt);

  PrivateValues private_values = GetValidPrivateValues();
  RestrictedData padded_p(
      absl::StrCat(test::HexDecodeOrDie("000000"),
                   private_values.p.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());
  RestrictedData padded_q(
      absl::StrCat(test::HexDecodeOrDie("0000"),
                   private_values.q.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());
  RestrictedData padded_dp(
      absl::StrCat(test::HexDecodeOrDie("0000000000"),
                   private_values.dp.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());
  RestrictedData padded_dq(
      absl::StrCat(test::HexDecodeOrDie("00"),
                   private_values.dq.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());
  RestrictedData padded_q_inv(absl::StrCat(test::HexDecodeOrDie("000000"),
                                           private_values.q_inv.GetSecret(
                                               InsecureSecretKeyAccess::Get())),
                              InsecureSecretKeyAccess::Get());
  RestrictedData padded_d(
      absl::StrCat(test::HexDecodeOrDie("000000"),
                   private_values.d.GetSecret(InsecureSecretKeyAccess::Get())),
      InsecureSecretKeyAccess::Get());
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(padded_p)
          .SetPrimeQ(padded_q)
          .SetPrimeExponentP(padded_dp)
          .SetPrimeExponentQ(padded_dq)
          .SetPrivateExponent(padded_d)
          .SetCrtCoefficient(padded_q_inv)
          .BuildAllowNonConstantTime(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
}

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST(JwtRsaSsaPkcs1PrivateKeyTest,
     BuildAllowNonConstantTimeWithRestrictedBigIntegerAndDataFails) {
  JwtRsaSsaPkcs1PublicKey public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId,
      /*id_requirement=*/0x1ac6a944, /*custom_kid=*/std::nullopt);

  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();
  RestrictedBigInteger dq_rb(vector.dq, InsecureSecretKeyAccess::Get());
  PrivateValues private_values = GetValidPrivateValues();

  EXPECT_THAT(
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.d)
          .SetPrimeExponentQ(dq_rb)
          .SetPrivateExponent(private_values.dq)
          .SetCrtCoefficient(private_values.q_inv)
          .BuildAllowNonConstantTime(GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument,
               StrEq("BuildAllowNonConstantTime method can only be used by "
                     "setting RestrictedData fields.")));
}

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest, BuildWithRestrictedBigInteger) {
  TestCase test_case = GetParam();

  JwtRsaSsaPkcs1PublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();
  RestrictedBigInteger p_rb(vector.p, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_rb(vector.q, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dp_rb(vector.dp, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dq_rb(vector.dq, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger d_rb(vector.d, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_inv_rb(vector.q_inv,
                                InsecureSecretKeyAccess::Get());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(p_rb)
          .SetPrimeQ(q_rb)
          .SetPrimeExponentP(dp_rb)
          .SetPrimeExponentQ(dq_rb)
          .SetPrivateExponent(d_rb)
          .SetCrtCoefficient(q_inv_rb)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  EXPECT_THAT(private_key->GetParameters(), Eq(public_key.GetParameters()));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(public_key));
  EXPECT_THAT(private_key->GetKid(), Eq(test_case.expected_kid));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(),
              Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
}

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest,
       BuildWithRestrictedBigIntegerAndRestrictedDataFails) {
  TestCase test_case = GetParam();

  JwtRsaSsaPkcs1PublicKey public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();
  RestrictedBigInteger p_rb(vector.p, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dp_rb(vector.dp, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dq_rb(vector.dq, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger d_rb(vector.d, InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_inv_rb(vector.q_inv,
                                InsecureSecretKeyAccess::Get());
  PrivateValues private_values = GetValidPrivateValues();

  EXPECT_THAT(JwtRsaSsaPkcs1PrivateKey::Builder()
                  .SetPublicKey(public_key)
                  .SetPrimeP(p_rb)
                  .SetPrimeQ(private_values.q)
                  .SetPrimeExponentP(dp_rb)
                  .SetPrimeExponentQ(dq_rb)
                  .SetPrivateExponent(d_rb)
                  .SetCrtCoefficient(q_inv_rb)
                  .Build(GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyFromBoringSslWorks) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  ASSERT_THAT(rsa, NotNull());

  const jwt_internal::RsaSsaTestVector& vector =
      jwt_internal::GetRsa2048BitVector2();

  BIGNUM* n = BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.n.data()),
                        vector.n.size(), nullptr);
  BIGNUM* e = BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.e.data()),
                        vector.e.size(), nullptr);
  BIGNUM* d = BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.d.data()),
                        vector.d.size(), nullptr);
  ASSERT_THAT(RSA_set0_key(rsa.get(), n, e, d), Eq(1));

  BIGNUM* p = BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.p.data()),
                        vector.p.size(), nullptr);
  BIGNUM* q = BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.q.data()),
                        vector.q.size(), nullptr);
  ASSERT_THAT(RSA_set0_factors(rsa.get(), p, q), Eq(1));

  BIGNUM* dp =
      BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.dp.data()),
                vector.dp.size(), nullptr);
  BIGNUM* dq =
      BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.dq.data()),
                vector.dq.size(), nullptr);
  BIGNUM* q_inv =
      BN_bin2bn(reinterpret_cast<const unsigned char*>(vector.q_inv.data()),
                vector.q_inv.size(), nullptr);
  ASSERT_THAT(RSA_set0_crt_params(rsa.get(), dp, dq, q_inv), Eq(1));

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
  absl::StatusOr<std::string> d_str = internal::BignumToString(d_bn, 2048 / 8);
  ASSERT_THAT(d_str, IsOk());
  absl::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(p_str, IsOk());
  absl::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  ASSERT_THAT(q_str, IsOk());
  absl::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(dp_str, IsOk());
  absl::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(q_bn));
  ASSERT_THAT(dq_str, IsOk());
  absl::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(p_bn));
  ASSERT_THAT(q_inv_str, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(*e_str))
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(BigInteger(*n_str))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(*p_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(*q_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(
              RestrictedData(*dp_str, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(
              RestrictedData(*dq_str, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(*d_str, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(*q_inv_str, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*p_str));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess())
                  .GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(*q_str));
  EXPECT_THAT(private_key->GetPrimeExponentPData().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dp_str));
  EXPECT_THAT(private_key->GetPrimeExponentQData().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*dq_str));
  EXPECT_THAT(private_key->GetCrtCoefficientData().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*q_inv_str));
  EXPECT_THAT(private_key->GetPrivateExponentData().GetSecret(
                  InsecureSecretKeyAccess::Get()),
              Eq(*d_str));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(std::nullopt));
  EXPECT_THAT(private_key->GetKid(), Eq(std::nullopt));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  JwtRsaSsaPkcs1PublicKey valid_public_key =
      GetValidPublicKey(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
                        JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
                        /*id_requirement=*/std::nullopt,
                        /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key_modified_modulus =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(valid_public_key.GetParameters())
          .SetModulus(
              BigInteger(FlipFirstByte(jwt_internal::GetRsa2048BitVector2().n)))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_modulus =
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
                       HasSubstr("Modulus size is")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /* id_requirement= */ std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_prime_p =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(RestrictedData(
              FlipFirstByte(jwt_internal::GetRsa2048BitVector2().p),
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_modified_prime_q =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(RestrictedData(
              FlipFirstByte(jwt_internal::GetRsa2048BitVector2().q),
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

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_prime_exponent_p =
          JwtRsaSsaPkcs1PrivateKey::Builder()
              .SetPublicKey(valid_public_key)
              .SetPrimeP(private_values.p)
              .SetPrimeQ(private_values.q)
              .SetPrimeExponentP(RestrictedData(
                  FlipFirstByte(jwt_internal::GetRsa2048BitVector2().dp),
                  InsecureSecretKeyAccess::Get()))
              .SetPrimeExponentQ(private_values.dq)
              .SetPrivateExponent(private_values.d)
              .SetCrtCoefficient(private_values.q_inv)
              .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_prime_exponent_q =
          JwtRsaSsaPkcs1PrivateKey::Builder()
              .SetPublicKey(valid_public_key)
              .SetPrimeP(private_values.p)
              .SetPrimeQ(private_values.q)
              .SetPrimeExponentP(private_values.dp)
              .SetPrimeExponentQ(RestrictedData(
                  FlipFirstByte(jwt_internal::GetRsa2048BitVector2().dq),
                  InsecureSecretKeyAccess::Get()))
              .SetPrivateExponent(private_values.d)
              .SetCrtCoefficient(private_values.q_inv)
              .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_private_exponent =
          JwtRsaSsaPkcs1PrivateKey::Builder()
              .SetPublicKey(valid_public_key)
              .SetPrimeP(private_values.p)
              .SetPrimeQ(private_values.q)
              .SetPrimeExponentP(private_values.dp)
              .SetPrimeExponentQ(private_values.dq)
              .SetPrivateExponent(RestrictedData(
                  FlipFirstByte(jwt_internal::GetRsa2048BitVector2().d),
                  InsecureSecretKeyAccess::Get()))
              .SetCrtCoefficient(private_values.q_inv)
              .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_private_exponent.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey>
      private_key_modified_crt_coefficient =
          JwtRsaSsaPkcs1PrivateKey::Builder()
              .SetPublicKey(valid_public_key)
              .SetPrimeP(private_values.p)
              .SetPrimeQ(private_values.q)
              .SetPrimeExponentP(private_values.dp)
              .SetPrimeExponentQ(private_values.dq)
              .SetPrivateExponent(private_values.d)
              .SetCrtCoefficient(RestrictedData(
                  FlipFirstByte(jwt_internal::GetRsa2048BitVector2().q_inv),
                  InsecureSecretKeyAccess::Get()))
              .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_crt_coefficient.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not load RSA key")));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_public_key_set =
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
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_p_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeQNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_q_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_p_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_q_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildPrivateExponentNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_private_exponent_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_private_exponent_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  JwtRsaSsaPkcs1PublicKey valid_public_key = GetValidPublicKey(
      JwtRsaSsaPkcs1Parameters::Algorithm::kRs256,
      JwtRsaSsaPkcs1Parameters::KidStrategy::kIgnored,
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);
  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key_no_crt_coefficient_set =
      JwtRsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(valid_public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_crt_coefficient_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::AllOf(HasSubstr("RestrictedData"),
                                      HasSubstr("RestrictedBigInteger"))));
}

TEST(JwtRsaSsaPkcs1PrivateKeyTest, CreateMismatchedKeyPairFails) {
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
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
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(mismatched_modulus)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
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
                       HasSubstr("Could not load RSA key")));
}

TEST_P(JwtRsaSsaPkcs1PrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  JwtRsaSsaPkcs1PublicKey valid_public_key =
      GetValidPublicKey(test_case.algorithm, test_case.kid_strategy,
                        test_case.id_requirement, test_case.custom_kid);

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
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

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> same_private_key =
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
  absl::StatusOr<JwtRsaSsaPkcs1Parameters> parameters =
      JwtRsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetAlgorithm(JwtRsaSsaPkcs1Parameters::Algorithm::kRs256)
          .SetKidStrategy(
              JwtRsaSsaPkcs1Parameters::KidStrategy::kBase64EncodedKeyId)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus(jwt_internal::GetRsa2048BitVector2().n);
  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key1 =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(123)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key1, IsOk());

  absl::StatusOr<JwtRsaSsaPkcs1PublicKey> public_key2 =
      JwtRsaSsaPkcs1PublicKey::Builder()
          .SetParameters(*parameters)
          .SetModulus(modulus)
          .SetIdRequirement(456)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key2, IsOk());

  PrivateValues private_values = GetValidPrivateValues();
  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key1 =
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

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key2 =
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
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
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
      /*id_requirement=*/std::nullopt, /*custom_kid=*/std::nullopt);

  PrivateValues private_values = GetValidPrivateValues();

  absl::StatusOr<JwtRsaSsaPkcs1PrivateKey> private_key =
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
