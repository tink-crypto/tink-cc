// Copyright 2023 Google LLC
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

#include "tink/signature/rsa_ssa_pkcs1_private_key.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/restricted_data.h"
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
#include "tink/key.h"
#include "tink/partial_key_access.h"
#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"

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
  RsaSsaPkcs1Parameters::HashType hash_type;
  RsaSsaPkcs1Parameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
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

const RsaSsaPkcs1PrivateKey& Get2048BitPrivateKey() {
  static const absl::NoDestructor<RsaSsaPkcs1PrivateKey> key([]() {
    return *static_cast<const RsaSsaPkcs1PrivateKey*>(
        internal::Create2048BitsTestVector().signature_private_key.get());
  }());
  return *key;
}

const RsaSsaPkcs1PrivateKey& Get3072BitPrivateKey() {
  static const absl::NoDestructor<RsaSsaPkcs1PrivateKey> key([]() {
    return *static_cast<const RsaSsaPkcs1PrivateKey*>(
        internal::Create3072BitsTestVector().signature_private_key.get());
  }());
  return *key;
}

PrivateValues GetValid2048BitPrivateValues() {
  const RsaSsaPkcs1PrivateKey& key = Get2048BitPrivateKey();
  return PrivateValues{/*p=*/key.GetPrimePData(GetPartialKeyAccess()),
                       /*q=*/key.GetPrimeQData(GetPartialKeyAccess()),
                       /*dp=*/key.GetPrimeExponentPData(),
                       /*dq=*/key.GetPrimeExponentQData(),
                       /*d=*/key.GetPrivateExponentData(),
                       /*q_inv=*/key.GetCrtCoefficientData()};
}

PrivateValues GetValid3072BitPrivateValues() {
  const RsaSsaPkcs1PrivateKey& key = Get3072BitPrivateKey();
  return PrivateValues{/*p=*/key.GetPrimePData(GetPartialKeyAccess()),
                       /*q=*/key.GetPrimeQData(GetPartialKeyAccess()),
                       /*dp=*/key.GetPrimeExponentPData(),
                       /*dq=*/key.GetPrimeExponentQData(),
                       /*d=*/key.GetPrivateExponentData(),
                       /*q_inv=*/key.GetCrtCoefficientData()};
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> CreateValid2048BitPrivateKey(
    const RsaSsaPkcs1Parameters& parameters,
    absl::optional<int> id_requirement) {
  const RsaSsaPkcs1PrivateKey& key = Get2048BitPrivateKey();
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(
          parameters, key.GetPublicKey().GetModulus(GetPartialKeyAccess()),
          id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  PrivateValues private_values = GetValid2048BitPrivateValues();
  return RsaSsaPkcs1PrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(private_values.p)
      .SetPrimeQ(private_values.q)
      .SetPrimeExponentP(private_values.dp)
      .SetPrimeExponentQ(private_values.dq)
      .SetPrivateExponent(private_values.d)
      .SetCrtCoefficient(private_values.q_inv)
      .Build(GetPartialKeyAccess());
}

absl::StatusOr<RsaSsaPkcs1PrivateKey> CreateValid3072BitPrivateKey(
    const RsaSsaPkcs1Parameters& parameters,
    absl::optional<int> id_requirement) {
  const RsaSsaPkcs1PrivateKey& key = Get3072BitPrivateKey();
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(
          parameters, key.GetPublicKey().GetModulus(GetPartialKeyAccess()),
          id_requirement, GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  PrivateValues private_values = GetValid3072BitPrivateValues();
  return RsaSsaPkcs1PrivateKey::Builder()
      .SetPublicKey(*public_key)
      .SetPrimeP(private_values.p)
      .SetPrimeQ(private_values.q)
      .SetPrimeExponentP(private_values.dp)
      .SetPrimeExponentQ(private_values.dq)
      .SetPrivateExponent(private_values.d)
      .SetCrtCoefficient(private_values.q_inv)
      .Build(GetPartialKeyAccess());
}

RsaSsaPkcs1PublicKey GetValidPublicKey() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters.status()) << "Failed to create parameters.";

  const RsaSsaPkcs1PrivateKey& key = Get2048BitPrivateKey();
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(
          *parameters, key.GetPublicKey().GetModulus(GetPartialKeyAccess()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status()) << "Failed to create public key.";
  return *public_key;
}

std::string FlipFirstByte(absl::string_view str) {
  std::string res(str);
  res[0] = ~res[0];
  return res;
}

using RsaSsaPkcs1PrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1PrivateKeyTestSuite, RsaSsaPkcs1PrivateKeyTest,
    Values(TestCase{RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kTink,
                    /*id_requirement=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha256,
                    RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    /*id_requirement=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha384,
                    RsaSsaPkcs1Parameters::Variant::kLegacy,
                    /*id_requirement=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPkcs1Parameters::HashType::kSha512,
                    RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    /*id_requirement=*/std::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeySucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus =
      Get2048BitPrivateKey().GetPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValid2048BitPrivateValues();
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.p.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.q.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentP(),
              Eq(RestrictedBigInteger(
                  private_values.dp.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentQ(),
              Eq(RestrictedBigInteger(
                  private_values.dq.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetCrtCoefficient(),
              Eq(RestrictedBigInteger(
                  private_values.q_inv.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrivateExponent(),
              Eq(RestrictedBigInteger(
                  private_values.d.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyFromBoringSsl) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  ASSERT_THAT(rsa, NotNull());

  PrivateValues private_values = GetValid2048BitPrivateValues();
  std::string n_str_static = std::string(Get2048BitPrivateKey()
                                             .GetPublicKey()
                                             .GetModulus(GetPartialKeyAccess())
                                             .GetValue());
  std::string e_str_static =
      test::HexDecodeOrDie("010001");  // 65537 in big-endian bytes

  BIGNUM* n =
      BN_bin2bn(reinterpret_cast<const unsigned char*>(n_str_static.data()),
                n_str_static.size(), nullptr);
  BIGNUM* e =
      BN_bin2bn(reinterpret_cast<const unsigned char*>(e_str_static.data()),
                e_str_static.size(), nullptr);
  BIGNUM* d = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.d.GetSecret(InsecureSecretKeyAccess::Get()).data()),
      private_values.d.size(), nullptr);
  ASSERT_THAT(RSA_set0_key(rsa.get(), n, e, d), Eq(1));

  BIGNUM* p = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.p.GetSecret(InsecureSecretKeyAccess::Get()).data()),
      private_values.p.size(), nullptr);
  BIGNUM* q = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.q.GetSecret(InsecureSecretKeyAccess::Get()).data()),
      private_values.q.size(), nullptr);
  ASSERT_THAT(RSA_set0_factors(rsa.get(), p, q), Eq(1));

  BIGNUM* dp = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.dp.GetSecret(InsecureSecretKeyAccess::Get()).data()),
      private_values.dp.size(), nullptr);
  BIGNUM* dq = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.dq.GetSecret(InsecureSecretKeyAccess::Get()).data()),
      private_values.dq.size(), nullptr);
  BIGNUM* q_inv = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(
          private_values.q_inv.GetSecret(InsecureSecretKeyAccess::Get())
              .data()),
      private_values.q_inv.size(), nullptr);
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
  absl::StatusOr<std::string> d_str = internal::BignumToString(d_bn, 256);
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

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(*e_str))
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, /*modulus=*/BigInteger(*n_str),
                                   /*id_requirement=*/std::nullopt,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(""));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesModulus) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key_modified_modulus =
      RsaSsaPkcs1PublicKey::Create(
          public_key.GetParameters(),
          BigInteger(FlipFirstByte(Get2048BitPrivateKey()
                                       .GetPublicKey()
                                       .GetModulus(GetPartialKeyAccess())
                                       .GetValue())),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key_modified_modulus, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_modulus =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key_modified_modulus)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_modulus.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeP) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_p =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(RestrictedData(
              FlipFirstByte(Get2048BitPrivateKey()
                                .GetPrimePData(GetPartialKeyAccess())
                                .GetSecret(InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeQ) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_q =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(RestrictedData(
              FlipFirstByte(Get2048BitPrivateKey()
                                .GetPrimeQData(GetPartialKeyAccess())
                                .GetSecret(InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentP) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_exponent_p =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(RestrictedData(
              FlipFirstByte(
                  Get2048BitPrivateKey().GetPrimeExponentPData().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_p.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrimeExponentQ) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_prime_exponent_q =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(RestrictedData(
              FlipFirstByte(
                  Get2048BitPrivateKey().GetPrimeExponentQData().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_prime_exponent_q.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesPrivateExponent) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_private_exponent =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(RestrictedData(
              FlipFirstByte(
                  Get2048BitPrivateKey().GetPrivateExponentData().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_private_exponent.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyValidatesCrtCoefficient) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_modified_crt_coefficient =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(RestrictedData(
              FlipFirstByte(
                  Get2048BitPrivateKey().GetCrtCoefficientData().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_modified_crt_coefficient.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPublicKeyNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_public_key_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_public_key_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimePNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_p_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeQNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_q_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentPNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_p_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_p_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrimeExponentQNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_prime_exponent_q_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_prime_exponent_q_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildPrivateExponentNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_private_exponent_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_private_exponent_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, BuildCrtCoefficientNotSetFails) {
  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key_no_crt_coefficient_set =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(GetValidPublicKey())
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key_no_crt_coefficient_set.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaSsaPkcs1PrivateKeyTest, CreateMismatchedKeyPairFails) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger mismatched_modulus(
      FlipFirstByte(Get2048BitPrivateKey()
                        .GetPublicKey()
                        .GetModulus(GetPartialKeyAccess())
                        .GetValue()));
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, mismatched_modulus,
                                   /*id_requirement=*/0x02030400,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValid2048BitPrivateValues();

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(private_key.status(),
              StatusIs(absl::StatusCode ::kInvalidArgument));
}

TEST_P(RsaSsaPkcs1PrivateKeyTest, BuildPrivateKeyAllowNonConstantTimeSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus =
      Get2048BitPrivateKey().GetPublicKey().GetModulus(GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  PrivateValues private_values = GetValid2048BitPrivateValues();
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(private_values.p)
          .SetPrimeQ(private_values.q)
          .SetPrimeExponentP(private_values.dp)
          .SetPrimeExponentQ(private_values.dq)
          .SetPrivateExponent(private_values.d)
          .SetCrtCoefficient(private_values.q_inv)
          .BuildAllowNonConstantTime(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrimePData(GetPartialKeyAccess()),
              Eq(private_values.p));
  EXPECT_THAT(private_key->GetPrimeQData(GetPartialKeyAccess()),
              Eq(private_values.q));
  EXPECT_THAT(private_key->GetPrimeExponentPData(), Eq(private_values.dp));
  EXPECT_THAT(private_key->GetPrimeExponentQData(), Eq(private_values.dq));
  EXPECT_THAT(private_key->GetCrtCoefficientData(), Eq(private_values.q_inv));
  EXPECT_THAT(private_key->GetPrivateExponentData(), Eq(private_values.d));
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.p.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.q.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentP(),
              Eq(RestrictedBigInteger(
                  private_values.dp.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentQ(),
              Eq(RestrictedBigInteger(
                  private_values.dq.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetCrtCoefficient(),
              Eq(RestrictedBigInteger(
                  private_values.q_inv.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrivateExponent(),
              Eq(RestrictedBigInteger(
                  private_values.d.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
}

TEST(RsaSsaPkcs1PrivateKeyTest,
     BuildPrivateKeyAllowNonConstantTimeSucceedsWithLeadingBytes) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();

  PrivateValues private_values = GetValid2048BitPrivateValues();

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
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
  // NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
  // TINK-PENDING-REMOVAL-IN-3.0.0-START
  EXPECT_THAT(private_key->GetPrimeP(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.p.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeQ(GetPartialKeyAccess()),
              Eq(RestrictedBigInteger(
                  private_values.q.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentP(),
              Eq(RestrictedBigInteger(
                  private_values.dp.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrimeExponentQ(),
              Eq(RestrictedBigInteger(
                  private_values.dq.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetCrtCoefficient(),
              Eq(RestrictedBigInteger(
                  private_values.q_inv.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  EXPECT_THAT(private_key->GetPrivateExponent(),
              Eq(RestrictedBigInteger(
                  private_values.d.Get(InsecureSecretKeyAccess::Get()),
                  InsecureSecretKeyAccess::Get())));
  // TINK-PENDING-REMOVAL-IN-3.0.0-END
  // NOLINTEND(whitespace/line_length)
}

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST(RsaSsaPkcs1PrivateKeyTest,
     BuildAllowNonConstantTimeWithRestrictedBigIntegerAndDataFails) {
  RsaSsaPkcs1PublicKey public_key = GetValidPublicKey();

  RestrictedBigInteger dq_rb(
      Get2048BitPrivateKey().GetPrimeExponentQData().GetSecret(
          InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  PrivateValues private_values = GetValid2048BitPrivateValues();

  EXPECT_THAT(
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST_P(RsaSsaPkcs1PrivateKeyTest, BuildWithRestrictedBigIntegerSucceeds) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPrivateKey().GetPublicKey().GetModulus(
      GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  const RsaSsaPkcs1PrivateKey& key = Get2048BitPrivateKey();
  RestrictedBigInteger p_rb(
      key.GetPrimePData(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_rb(
      key.GetPrimeQData(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dp_rb(
      key.GetPrimeExponentPData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dq_rb(
      key.GetPrimeExponentQData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger d_rb(
      key.GetPrivateExponentData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_inv_rb(
      key.GetCrtCoefficientData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(p_rb)
          .SetPrimeQ(q_rb)
          .SetPrimeExponentP(dp_rb)
          .SetPrimeExponentQ(dq_rb)
          .SetPrivateExponent(d_rb)
          .SetCrtCoefficient(q_inv_rb)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  PrivateValues private_values = GetValid2048BitPrivateValues();
  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
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

TEST_P(RsaSsaPkcs1PrivateKeyTest,
       BuildWithRestrictedBigIntegerAndRestrictedDataFails) {
  TestCase test_case = GetParam();

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  BigInteger modulus = Get2048BitPrivateKey().GetPublicKey().GetModulus(
      GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, modulus,
                                   test_case.id_requirement,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());
  const RsaSsaPkcs1PrivateKey& key = Get2048BitPrivateKey();
  RestrictedBigInteger p_rb(
      key.GetPrimePData(GetPartialKeyAccess())
          .GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dp_rb(
      key.GetPrimeExponentPData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger dq_rb(
      key.GetPrimeExponentQData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger d_rb(
      key.GetPrivateExponentData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  RestrictedBigInteger q_inv_rb(
      key.GetCrtCoefficientData().GetSecret(InsecureSecretKeyAccess::Get()),
      InsecureSecretKeyAccess::Get());
  PrivateValues private_values = GetValid2048BitPrivateValues();

  EXPECT_THAT(RsaSsaPkcs1PrivateKey::Builder()
                  .SetPublicKey(*public_key)
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

TEST_P(RsaSsaPkcs1PrivateKeyTest, PrivateKeyEquals) {
  TestCase test_case = GetParam();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(kModulusSizeInBits)
          .SetPublicExponent(kF4)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> same_private_key =
      CreateValid2048BitPrivateKey(*parameters, test_case.id_requirement);
  ASSERT_THAT(same_private_key, IsOk());

  EXPECT_TRUE(*private_key == *same_private_key);
  EXPECT_TRUE(*same_private_key == *private_key);
  EXPECT_FALSE(*private_key != *same_private_key);
  EXPECT_FALSE(*same_private_key != *private_key);
}

TEST(RsaSsaPkcs1PrivateKeyTest, DifferentPublicKeyNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  // Different id requirements result in different public keys.
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key1 =
      CreateValid2048BitPrivateKey(*parameters, /*id_requirement=*/0x02030400);
  ASSERT_THAT(private_key1, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key2 =
      CreateValid2048BitPrivateKey(*parameters, /*id_requirement=*/0x01030005);
  ASSERT_THAT(private_key2, IsOk());

  EXPECT_TRUE(*private_key1 != *private_key2);
  EXPECT_TRUE(*private_key2 != *private_key1);
  EXPECT_FALSE(*private_key1 == *private_key2);
  EXPECT_FALSE(*private_key2 == *private_key1);
}

TEST(RsaSsaPkcs1PrivateKeyTest, DifferentKeyTypesNotEqual) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(
          *parameters,
          Get2048BitPrivateKey().GetPublicKey().GetModulus(
              GetPartialKeyAccess()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  EXPECT_TRUE(*private_key != *public_key);
  EXPECT_TRUE(*public_key != *private_key);
  EXPECT_FALSE(*private_key == *public_key);
  EXPECT_FALSE(*public_key == *private_key);
}

TEST(RsaSsaPkcs1PrivateKeyTest, Clone) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  // Clone the key.
  std::unique_ptr<Key> cloned_key = private_key->Clone();

  ASSERT_THAT(*cloned_key, Eq(*private_key));
}

TEST(RsaSsaPkcs1PrivateKeyTest, CopyConstructor) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  RsaSsaPkcs1PrivateKey copy(*private_key);

  EXPECT_THAT(copy, Eq(*private_key));
}

TEST(RsaSsaPkcs1PrivateKeyTest, CopyAssignment) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> copy = CreateValid3072BitPrivateKey(
      *other_parameters, /*id_requirement=*/0x01020304);
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}

// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST(RsaSsaPkcs1PrivateKeyTest,
     CopyAssignmentWithRestrictedBigIntegerFieldsInitialized) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(private_key, IsOk());
  private_key->GetPrivateExponent();
  private_key->GetPrimeP(GetPartialKeyAccess());
  private_key->GetPrimeQ(GetPartialKeyAccess());
  private_key->GetPrimeExponentP();
  private_key->GetPrimeExponentQ();
  private_key->GetCrtCoefficient();

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> copy = CreateValid3072BitPrivateKey(
      *other_parameters, /*id_requirement=*/0x01020304);
  ASSERT_THAT(copy, IsOk());

  *copy = *private_key;

  EXPECT_THAT(*copy, Eq(*private_key));
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

TEST(RsaSsaPkcs1PrivateKeyTest, MoveConstructor) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  RsaSsaPkcs1PrivateKey expected = *private_key;
  RsaSsaPkcs1PrivateKey moved(std::move(*private_key));

  EXPECT_THAT(moved, Eq(expected));
}

TEST(RsaSsaPkcs1PrivateKeyTest, MoveAssignment) {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      CreateValid2048BitPrivateKey(*parameters,
                                   /*id_requirement=*/std::nullopt);
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> other_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(3072)
          .SetPublicExponent(kF4)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ASSERT_THAT(other_parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> moved = CreateValid3072BitPrivateKey(
      *other_parameters, /*id_requirement=*/0x01020304);
  ASSERT_THAT(moved, IsOk());

  RsaSsaPkcs1PrivateKey expected = *private_key;
  *moved = std::move(*private_key);

  EXPECT_THAT(*moved, Eq(expected));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
