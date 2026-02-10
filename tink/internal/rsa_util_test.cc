// Copyright 2021 Google LLC
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
///////////////////////////////////////////////////////////////////////////////
#include "tink/internal/rsa_util.h"

#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/secret_data.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::EqualsSecretData;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::IsEmpty;
using ::testing::Not;

constexpr int kSslSuccess = 1;
// 2048 bits modulus.
constexpr absl::string_view k2048BitRsaModulus =
    "b5a5651bc2e15ce31d789f0984053a2ea0cf8f964a78068c45acfdf078c57fd62d5a287c32"
    "f3baa879f5dfea27d7a3077c9d3a2a728368c3d90164690c3d82f660ffebc7f13fed454eb5"
    "103df943c10dc32ec60b0d9b6e307bfd7f9b943e0dc3901e42501765365f7286eff2f1f728"
    "774aa6a371e108a3a7dd00d7bcd4c1a186c2865d4b370ea38cc89c0b23b318dbcafbd872b4"
    "f9b833dfb2a4ca7fcc23298020044e8130bfe930adfb3e5cab8d324547adf4b2ce34d7cea4"
    "298f0b613d85f2bf1df03da44aee0784a1a20a15ee0c38a0f8e84962f1f61b18bd43781c73"
    "85f3c2b8e2aebd3c560b4faad208ad3938bad27ddda9ed9e933dba0880212dd9e28d";

// Utility function to create an RSA key pair.
absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> GetKeyPair(
    size_t modulus_size_in_bits) {
  RsaPublicKey public_key;
  RsaPrivateKey private_key;
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);
  absl::Status res =
      NewRsaKeyPair(modulus_size_in_bits, e.get(), &private_key, &public_key);
  if (!res.ok()) {
    return res;
  }
  return {{public_key, private_key}};
}

// Hardcoded test key pair with valid encoding lengths.
std::pair<RsaPublicKey, RsaPrivateKey> GetValidKeyPair() {
  const std::string p = test::HexDecodeOrDie(
      "f063c33f27afe76a92df6d2706e7105ea9c68603c6ddef9962f202e91794fe0600bf983c"
      "de161863ac015421fd005da1be745b639d6fb6e2eb34f61831642c0778e005516b65280b"
      "02c1a16807e82357c116368eda31345df5d57f9313c050f53dbd026e25ed3f126c84a37d"
      "d11b6f3b87a803ecdddce8ae6063294e74b91435");

  const std::string q = test::HexDecodeOrDie(
      "c2b333115745d5818ab71f2f89028d62af07bb0025500682937e37c7e99b54fa3893404b"
      "64c5b003b77ce43f55116a4ff4958b2267b63a2e848f919595801a79a6859f8e12d16167"
      "6d465fc0a1164fb86311ca274ee6773b6cb2abb8f438399022e4a97cb6df94aeb9710405"
      "5e7bd50248aad4e9d18f6b7da5c676e274ad4243");

  const std::string n = test::HexDecodeOrDie(
      "b6d3dfab89b51431fd17c10771143a14aa3736af3b186afd17a7725c28d686fd088605f1"
      "38079bcac25555495802ace0cba6b5462e6527bc73ac7fcac0c6c5c97798e1471b080322"
      "9b78a12d661c6a932dfcc954c28bf59fed6bd9feeaf92da160ce082c74e7c3961d78e6b7"
      "01604941cd68ddc0ef3c383362b3a5c3b075bd68af89d3aabd9f78c5e8a7cc0f611d356a"
      "271f287d640b934308e85651b535007e85ec74f064feff71629fe4715d6a3656519d5264"
      "75907a548968a30577b9cfe5ff1a2ff302897691e548308be208b44a23e0bb49e9e858ac"
      "f6483d89df777789a083058d04fb11368268f633443792b15008ebd07f3c235466350ca4"
      "ef76f3df");

  const std::string e = test::HexDecodeOrDie("010001");

  const std::string d = test::HexDecodeOrDie(
      "3dbbfe574c791618291787c90d0060fa505db37be90efe3576f2c635635ec91710f53c"
      "756ecf76e638c79ab458e1126217b2339cbe96ce9b9e4d9d9b278c170647f999fc2a1f02"
      "fc0116730a42e40e82a3312c04906ab5266b03938935ebace244af5d6831937ee2261288"
      "893c1038bc5cf16f8bb1dc9a3793b9089cb2ed96e67b1108386c5761049242c14b156cff"
      "e572c133e03abedccd7039994ea2eabf7099c9f6dbdcc71a532850c4ea680254c86a196a"
      "7fa262fef566e79889fc3ea695a6ca2e7a0920fd4bb58a565601513aa42c7ac29998ae7d"
      "fad1d5b5f326dc8788fb4f0b36abadad77ff1f3a6f4f8fafdde53e645af136810367a703"
      "d88ba1b99d");

  const std::string dp = test::HexDecodeOrDie(
      "954a8fce601a69911167fac4fb0f736626f028f89d7fe5b68ff1970725e31d23a3415a"
      "0dab2b73b82af1a44b7b71c7b494b074b557e8325f990d8a2c9a3808f41708a1a4e01ab1"
      "94ad008dfa2ab6eb842b615d3eb8994859763c427f980b9efbbf7cebce767571ef423fd9"
      "bd60a9361a75744e03c401d6ebbce6b89785fc0f65");

  const std::string dq = test::HexDecodeOrDie(
      "38976fab85ab75b08e8a45954284ac65d7ac2e8d8f4ae06989c7711d39687dddb11e13"
      "dd163063c5e0ca7b6971277bb83bc64fc7b34f833fcc2612d1e0bf78728d955f58235e1a"
      "aabe576b33895efbd30370c34a83a3775a9d709d7b47f923ba227a464d4ab657f8254c95"
      "379e4bee1118e016bcd3bd9527d34c8977af244113");

  const std::string crt = test::HexDecodeOrDie(
      "3aa13692a88932fe13ca704577c720d994012e2ee90898716c23da4c3544cf0e9eb456"
      "2b09c92bf8645884fe152cc6613445af1724994dcc92ec253fa1b47b961aa47b3c3abbdd"
      "5a413c7ee6a673461867a9dd6179ab7eb3e157fc3e0d06b794d3ea09ba8f5470fe9d47a8"
      "f548549f030e6ea67c169c4cae697bef7237514f4b");

  RsaPublicKey public_key;
  public_key.n = n;
  public_key.e = e;
  RsaPrivateKey private_key;
  private_key.n = public_key.n;
  private_key.e = public_key.e;
  private_key.d = util::SecretDataFromStringView(d);
  private_key.p = util::SecretDataFromStringView(p);
  private_key.q = util::SecretDataFromStringView(q);
  private_key.dp = util::SecretDataFromStringView(dp);
  private_key.dq = util::SecretDataFromStringView(dq);
  private_key.crt = util::SecretDataFromStringView(crt);
  return {public_key, private_key};
}

TEST(RsaUtilTest, BasicSanityChecks) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPublicKey& public_key = keys->first;
  const RsaPrivateKey& private_key = keys->second;

  EXPECT_THAT(private_key.n, Not(IsEmpty()));
  EXPECT_THAT(private_key.e, Not(IsEmpty()));
  EXPECT_THAT(private_key.d, Not(IsEmpty()));

  EXPECT_THAT(private_key.p, Not(IsEmpty()));
  EXPECT_THAT(private_key.q, Not(IsEmpty()));
  EXPECT_THAT(private_key.dp, Not(IsEmpty()));
  EXPECT_THAT(private_key.dq, Not(IsEmpty()));
  EXPECT_THAT(private_key.crt, Not(IsEmpty()));

  EXPECT_THAT(public_key.n, Not(IsEmpty()));
  EXPECT_THAT(public_key.e, Not(IsEmpty()));

  EXPECT_EQ(public_key.n, private_key.n);
  EXPECT_EQ(public_key.e, private_key.e);
}

TEST(RsaUtilTest, FailsOnLargeE) {
  // OpenSSL requires the "e" value to be at most 32 bits.
  RsaPublicKey public_key;
  RsaPrivateKey private_key;

  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), 1L << 33);
  EXPECT_THAT(NewRsaKeyPair(/*modulus_size_in_bits=*/2048, e.get(),
                            &private_key, &public_key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(RsaUtilTest, KeyIsWellFormed) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPrivateKey& private_key = keys->second;

  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(private_key.n);
  ASSERT_THAT(n, IsOk());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> d =
      internal::SecretDataToBignum(private_key.d);
  ASSERT_THAT(d, IsOk());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> p =
      internal::SecretDataToBignum(private_key.p);
  ASSERT_THAT(p, IsOk());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> q =
      internal::SecretDataToBignum(private_key.q);
  ASSERT_THAT(q, IsOk());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dp =
      internal::SecretDataToBignum(private_key.dp);
  ASSERT_THAT(dp, IsOk());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> dq =
      internal::SecretDataToBignum(private_key.dq);
  ASSERT_THAT(dq, IsOk());
  internal::SslUniquePtr<BN_CTX> ctx(BN_CTX_new());

  // Check n = p * q.
  {
    auto n_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mul(n_calc.get(), p->get(), q->get(), ctx.get()), kSslSuccess);
    EXPECT_EQ(BN_cmp(n_calc.get(), n->get()), 0);
  }

  // Check n size >= 2048 bit.
  EXPECT_GE(BN_num_bits(n->get()), 2048);

  // dp = d mod (p - 1)
  {
    auto pm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(p->get()));
    ASSERT_EQ(BN_sub_word(pm1.get(), /*w=*/1), kSslSuccess);
    auto dp_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mod(dp_calc.get(), d->get(), pm1.get(), ctx.get()),
              kSslSuccess);
    EXPECT_EQ(BN_cmp(dp_calc.get(), dp->get()), 0);
  }

  // dq = d mod (q - 1)
  {
    auto qm1 = internal::SslUniquePtr<BIGNUM>(BN_dup(q->get()));
    ASSERT_EQ(BN_sub_word(qm1.get(), /*w=*/1), kSslSuccess);
    auto dq_calc = internal::SslUniquePtr<BIGNUM>(BN_new());
    ASSERT_EQ(BN_mod(dq_calc.get(), d->get(), qm1.get(), ctx.get()),
              kSslSuccess);
    EXPECT_EQ(BN_cmp(dq_calc.get(), dq->get()), 0);
  }
}

TEST(RsaUtilTest, GeneratesDifferentPrivateKeys) {
  RsaPublicKey public_key;
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), RSA_F4);

  std::vector<RsaPrivateKey> private_keys;
  std::generate_n(std::back_inserter(private_keys), 4, [&]() {
    RsaPrivateKey private_key;
    EXPECT_THAT(NewRsaKeyPair(/*modulus_size_in_bits=*/2048, e.get(),
                              &private_key, &public_key),
                IsOk());
    return private_key;
  });

  for (size_t i = 0; i < private_keys.size() - 1; i++) {
    for (size_t j = i + 1; j < private_keys.size(); j++) {
      // The only field that should be equal.
      EXPECT_EQ(private_keys[i].e, private_keys[j].e);
      EXPECT_NE(private_keys[i].n, private_keys[j].n);
      EXPECT_THAT(private_keys[i].d, Not(EqualsSecretData(private_keys[j].d)));
      EXPECT_THAT(private_keys[i].p, Not(EqualsSecretData(private_keys[j].p)));
      EXPECT_THAT(private_keys[i].q, Not(EqualsSecretData(private_keys[j].q)));
      EXPECT_THAT(private_keys[i].dp,
                  Not(EqualsSecretData(private_keys[j].dp)));
      EXPECT_THAT(private_keys[i].dq,
                  Not(EqualsSecretData(private_keys[j].dq)));
      EXPECT_THAT(private_keys[i].crt,
                  Not(EqualsSecretData(private_keys[j].crt)));
    }
  }
}

TEST(RsaUtilTest, ValidateRsaModulusSize) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  {
    const RsaPrivateKey& private_key = keys->second;

    absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
        internal::StringToBignum(private_key.n);
    EXPECT_THAT(ValidateRsaModulusSize(BN_num_bits(n->get())), IsOk());
  }
  keys = GetKeyPair(/*modulus_size_in_bits=*/1024);
  ASSERT_THAT(keys, IsOk());
  {
    const RsaPrivateKey& private_key = keys->second;

    absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
        internal::StringToBignum(private_key.n);
    EXPECT_THAT(ValidateRsaModulusSize(BN_num_bits(n->get())), Not(IsOk()));
  }
}

TEST(RsaUtilTest, ValidateRsaPublicExponent) {
  internal::SslUniquePtr<BIGNUM> e_bn(BN_new());

  // Failure scenario.
  const std::vector<BN_ULONG> invalid_exponents = {2, 3, 4, 65536, 65538};
  for (const BN_ULONG exponent : invalid_exponents) {
    BN_set_word(e_bn.get(), exponent);
    absl::StatusOr<std::string> e_str =
        internal::BignumToString(e_bn.get(), BN_num_bytes(e_bn.get()));
    ASSERT_THAT(e_str, IsOk());
    EXPECT_THAT(ValidateRsaPublicExponent(*e_str), Not(IsOk()));
  }

  // Successful case.
  BN_set_word(e_bn.get(), RSA_F4);
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn.get(), BN_num_bytes(e_bn.get()));
  ASSERT_THAT(e_str, IsOk());
  EXPECT_THAT(ValidateRsaPublicExponent(*e_str), IsOk());
}

// Checks if a BIGNUM is equal to a string value.
void ExpectBignumEquals(const BIGNUM* bn, absl::string_view data) {
  absl::StatusOr<std::string> converted =
      internal::BignumToString(bn, BN_num_bytes(bn));
  ASSERT_THAT(converted, IsOk());
  EXPECT_EQ(*converted, data);
}

// Checks if a BIGNUM is equal to a SecretData value.
void ExpectBignumEquals(const BIGNUM* bn, const SecretData& data) {
  absl::StatusOr<SecretData> converted =
      internal::BignumToSecretData(bn, data.size());
  ASSERT_THAT(converted, IsOk());
  EXPECT_TRUE(util::SecretDataEquals(*converted, data));
}

TEST(RsaUtilTest, GetRsaModAndExponents) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  absl::Status result = GetRsaModAndExponents(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, &d);
  ExpectBignumEquals(n, private_key.n);
  ExpectBignumEquals(e, private_key.e);
  ExpectBignumEquals(d, private_key.d);
}

TEST(RsaUtilTest, GetRsaPrimeFactors) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  absl::Status result = GetRsaPrimeFactors(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  RSA_get0_factors(rsa.get(), &p, &q);
  ExpectBignumEquals(p, private_key.p);
  ExpectBignumEquals(q, private_key.q);
}

TEST(RsaUtilTest, GetRsaCrtParams) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPrivateKey& private_key = keys->second;
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  const BIGNUM* dp = nullptr;
  const BIGNUM* dq = nullptr;
  const BIGNUM* crt = nullptr;
  absl::Status result = GetRsaCrtParams(private_key, rsa.get());
  ASSERT_THAT(result, IsOk());
  RSA_get0_crt_params(rsa.get(), &dp, &dq, &crt);
  ExpectBignumEquals(dp, private_key.dp);
  ExpectBignumEquals(dq, private_key.dq);
  ExpectBignumEquals(crt, private_key.crt);
}

TEST(RsaUtilTest, CopiesRsaPrivateKey) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPrivateKey& private_key = keys->second;

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsa(private_key);
  ASSERT_THAT(rsa_result, IsOk());
  internal::SslUniquePtr<RSA> rsa = std::move(rsa_result).value();
  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, &d);
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  RSA_get0_factors(rsa.get(), &p, &q);
  ExpectBignumEquals(n, private_key.n);
  ExpectBignumEquals(e, private_key.e);
  ExpectBignumEquals(d, private_key.d);
  ExpectBignumEquals(p, private_key.p);
  ExpectBignumEquals(q, private_key.q);
}

TEST(RsaUtilTest, RsaPrivateKeyFixedSizeInputsWorks) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;
  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  ASSERT_THAT(rsa_result, IsOk());
  internal::SslUniquePtr<RSA> rsa = std::move(rsa_result).value();
  const BIGNUM* n_bn = nullptr;
  const BIGNUM* e_bn = nullptr;
  const BIGNUM* d_bn = nullptr;
  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);
  const BIGNUM* p_bn = nullptr;
  const BIGNUM* q_bn = nullptr;
  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);
  ExpectBignumEquals(n_bn, valid_private_key.n);
  ExpectBignumEquals(e_bn, valid_private_key.e);
  ExpectBignumEquals(d_bn, valid_private_key.d);
  ExpectBignumEquals(p_bn, valid_private_key.p);
  ExpectBignumEquals(q_bn, valid_private_key.q);
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedP) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_p =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.p));

  valid_private_key.p = util::SecretDataFromStringView(padded_p);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedD) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_d =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.d));
  valid_private_key.d = util::SecretDataFromStringView(padded_d);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedQ) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_q =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.q));
  valid_private_key.q = util::SecretDataFromStringView(padded_q);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedDp) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_dp =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.dp));
  valid_private_key.dp = util::SecretDataFromStringView(padded_dp);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedDq) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_dq =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.dq));
  valid_private_key.dq = util::SecretDataFromStringView(padded_dq);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, SslRsaPrivateKeyCreationWithPaddedCrt) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  std::string padded_crt =
      absl::StrCat(test::HexDecodeOrDie("00"),
                   util::SecretDataAsStringView(valid_private_key.crt));
  valid_private_key.crt = util::SecretDataFromStringView(padded_crt);

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);
  EXPECT_THAT(rsa_result, StatusIs(absl::StatusCode::kInvalidArgument));
  ASSERT_THAT(RsaPrivateKeyToRsa(valid_private_key), IsOk());
}

TEST(RsaUtilTest, RsaPrivateKeyFixedSizeInputEqualsRsaPrivateKey) {
  std::pair<RsaPublicKey, RsaPrivateKey> valid_key_pair = GetValidKeyPair();
  RsaPrivateKey valid_private_key = valid_key_pair.second;

  absl::StatusOr<internal::SslUniquePtr<RSA>> adjusted_rsa =
      RsaPrivateKeyToRsaFixedSizeInputs(valid_private_key);

  ASSERT_THAT(adjusted_rsa, IsOk());
  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  const BIGNUM* d = nullptr;
  RSA_get0_key(adjusted_rsa->get(), &n, &e, &d);
  const BIGNUM* p = nullptr;
  const BIGNUM* q = nullptr;
  RSA_get0_factors(adjusted_rsa->get(), &p, &q);
  const BIGNUM* dp = nullptr;
  const BIGNUM* dq = nullptr;
  const BIGNUM* crt = nullptr;
  RSA_get0_crt_params(adjusted_rsa->get(), &dp, &dq, &crt);

  // Here the adjustment for the encodings should be done in the
  // `RsaPrivateKeyToRsa` function.
  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa =
      RsaPrivateKeyToRsa(valid_private_key);
  ASSERT_THAT(rsa, IsOk());
  const BIGNUM* n2 = nullptr;
  const BIGNUM* e2 = nullptr;
  const BIGNUM* d2 = nullptr;
  RSA_get0_key(rsa->get(), &n2, &e2, &d2);
  const BIGNUM* p2 = nullptr;
  const BIGNUM* q2 = nullptr;
  RSA_get0_factors(rsa->get(), &p2, &q2);
  const BIGNUM* dp2 = nullptr;
  const BIGNUM* dq2 = nullptr;
  const BIGNUM* crt2 = nullptr;
  RSA_get0_crt_params(rsa->get(), &dp2, &dq2, &crt2);

  ExpectBignumEquals(n, valid_private_key.n);
  ExpectBignumEquals(e, valid_private_key.e);
  ExpectBignumEquals(d, valid_private_key.d);
  ExpectBignumEquals(p, valid_private_key.p);
  ExpectBignumEquals(q, valid_private_key.q);
  ExpectBignumEquals(dp, valid_private_key.dp);
  ExpectBignumEquals(dq, valid_private_key.dq);
  ExpectBignumEquals(crt, valid_private_key.crt);

  ExpectBignumEquals(n2, valid_private_key.n);
  ExpectBignumEquals(e2, valid_private_key.e);
  ExpectBignumEquals(d2, valid_private_key.d);
  ExpectBignumEquals(p2, valid_private_key.p);
  ExpectBignumEquals(q2, valid_private_key.q);
  ExpectBignumEquals(dp2, valid_private_key.dp);
  ExpectBignumEquals(dq2, valid_private_key.dq);
  ExpectBignumEquals(crt2, valid_private_key.crt);
}

TEST(RsaUtilTest, CopiesRsaPublicKey) {
  absl::StatusOr<std::pair<RsaPublicKey, RsaPrivateKey>> keys =
      GetKeyPair(/*modulus_size_in_bits=*/2048);
  ASSERT_THAT(keys, IsOk());
  const RsaPublicKey& public_key = keys->first;

  absl::StatusOr<internal::SslUniquePtr<RSA>> rsa_result =
      RsaPublicKeyToRsa(public_key);
  ASSERT_THAT(rsa_result, IsOk());
  internal::SslUniquePtr<RSA> rsa = std::move(rsa_result).value();

  const BIGNUM* n = nullptr;
  const BIGNUM* e = nullptr;
  RSA_get0_key(rsa.get(), &n, &e, /*out_d=*/nullptr);
  ExpectBignumEquals(n, public_key.n);
  ExpectBignumEquals(e, public_key.e);
}

// Utility function that creates an RSA public key with the given modulus
// `n_hex` and exponent `exp`.
absl::StatusOr<internal::SslUniquePtr<RSA>> NewRsaPublicKey(
    absl::string_view n_hex, uint64_t exp) {
  internal::SslUniquePtr<RSA> key(RSA_new());
  absl::StatusOr<internal::SslUniquePtr<BIGNUM>> n_bn =
      internal::StringToBignum(test::HexDecodeOrDie(n_hex));
  if (!n_bn.ok()) {
    return n_bn.status();
  }
  internal::SslUniquePtr<BIGNUM> n = *std::move(n_bn);
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  BN_set_word(e.get(), exp);
  if (RSA_set0_key(key.get(), n.get(), e.get(), /*d=*/nullptr) != 1) {
    return absl::Status(absl::StatusCode::kInternal, "RSA_set0_key failed");
  }
  // RSA_set0_key takes ownership of the arguments.
  n.release();
  e.release();
  return std::move(key);
}

TEST(RsaUtilTest, RsaCheckPublicKeyNullKey) {
  EXPECT_THAT(RsaCheckPublicKey(nullptr), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyMissingExponentAndModule) {
  internal::SslUniquePtr<RSA> key(RSA_new());
  EXPECT_THAT(RsaCheckPublicKey(key.get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyValid) {
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, RSA_F4);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), IsOk());
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentTooLarge) {
  // Invalid exponent of 34 bits.
  constexpr uint64_t kExponentTooLarge = 0x200000000;
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentTooLarge);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentTooSmall) {
  constexpr uint64_t kExponentEqualsToOne = 0x1;
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentEqualsToOne);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyExponentNotOdd) {
  constexpr uint64_t kExponentNotOdd = 0x20000000;
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(k2048BitRsaModulus, kExponentNotOdd);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyModulusTooLarge) {
  // Get 1 byte more than 16384 bits (2048 bytes).
  std::string too_large_modulus = subtle::Random::GetRandomBytes(2049);
  if (too_large_modulus[0] == '\0') {
    too_large_modulus[0] = 0x01;
  }
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(test::HexEncode(too_large_modulus), RSA_F4);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

TEST(RsaUtilTest, RsaCheckPublicKeyModulusSmallerThanExp) {
  constexpr absl::string_view kModulusSmallerThanExp = "1001";
  absl::StatusOr<internal::SslUniquePtr<RSA>> key =
      NewRsaPublicKey(kModulusSmallerThanExp, RSA_F4);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(RsaCheckPublicKey(key->get()), Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
