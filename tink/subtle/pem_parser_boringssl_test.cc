// Copyright 2018 Google LLC
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
#include "tink/subtle/pem_parser_boringssl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::testing::Not;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::Values;

// Holds test vectors for the PemParser. The original private-key pem text was
// taken from
// google3/third_party/tink/java_src/src/test/java/com/google/crypto/tink/subtle/PemKeyTypeTest.java.
// The components and public-key PEM version were extracted using
//
// $ openssl rsa -in <pem file> -pubout -text
struct RsaKeyTestVector {
  // RSA parameters.
  absl::string_view modulus_hex_str;
  absl::string_view public_exponent_hex_str;

  absl::string_view private_exponent_hex_str;
  absl::string_view p_hex_str;
  absl::string_view q_hex_str;
  absl::string_view dp_hex_str;
  absl::string_view dq_hex_str;
  absl::string_view coefficient_hex_str;

  // PEM forms.
  absl::string_view public_pem;
  absl::string_view private_pem;
};

const RsaKeyTestVector& GetRsaKeyTestVector() {
  static const RsaKeyTestVector kTestVector{
      /*.modulus_hex_str=*/
      "00bc067ea9038c24b063cac6146b26793499cc8a93985208596b9700acd4e51a580413"
      "316cc5acc5b499d4781421ba9b0d8af75ae56b6179d5a7fc2098f2fc4d366a6a4166b1"
      "5f2254db1cb3ce5dd4ab80bd8bd5adb5df34b602c319d4d004299c06e5e2437fd626e2"
      "84c29eeb79d1820b830b706072efa2fd1c8898d1eaaf39fb9f54ce7671ea2b5512a429"
      "0d3ec58bb41639a19be6630b1c27059b9a32505bebc6f42b301f9fb2cf2b624c1b6598"
      "702bbeaed38b5fd9941d661ff6adca65ffb251d1f314bced0861fa30ec676e2129e5ac"
      "ba03a6cb7594f93c60cef9b2aeee45edc6aadd31f841ee1f37fd63ccff3cebbb018a3d"
      "631b3d498a79348704bb419f",
      /*.public_exponent_hex_str=*/"010001",
      /*.private_exponent_hex_str=*/
      "718b1a81c5faa34d4175fa17ea7cd944c27b9a5376f052ca6d064b0a13a6263a707b86"
      "a540da0ca9fb1b2b483cf60b1c2a872504d5cb8f5f4e8a1ac54236ca09ca4950254b87"
      "3f9c2e952e9fb859ed17595f50320e5a33e295d86b88eff5138b7d3ee55c0d9eacecad"
      "6f39b8c95f9340906a1ffa9e6dc7e7418bdb7d28539897297c7da5358867e60dfe8c76"
      "fbf5a6a4c064e0f6af1bf3c9640cbee007aea3be81017b726d088b69957b844f951fac"
      "323ff3e79fd67daf32a3dce862320ab0f4a78255f740f7381396ab8d55f80c1b38a149"
      "f2418a2747795b44b14092fa17d215ae0e33c78997471ab971628b897776a80bbdee7e"
      "ddf60eca6cecba50f32281",
      /*.p_hex_str=*/
      "00e3f152467849f4c2d87f5a6506453878b7547996b14067966e336399e2be6a8c2ea8"
      "f065251f05e8bdcde4733d7084523432f3aad6b75990efadbedbce91cb097ce2b85dfa"
      "22fd3ca12a86198d76d31009531351f07246937cd7b1d81d3675f8afd759d1279edb13"
      "06e12f757baf368e265fb429775b1b4d16d88a7b009f00c7",
      /*.q_hex_str=*/
      "00d32b57f3d29f741c33ccf95d98b93b4efd56af0f9bc98f9089d8761ecccf65e0ba7f"
      "eebfbef8fce3bb38a4a5f9614d47a28f137238518ab47f0a12912dc951b1d540632bc5"
      "70338b17ee4f866767b7ba98ac6a057f1a2b27101ee584e9e82d4a83f31ef14d11f1d9"
      "105dc38e3052a506982ff3679e760c7ad186f361284c9069",
      /*.dp_hex_str=*/
      "00c536bf9694f077c2350a4aad69756e5c9351953959f67d295c033e43a0385b7b19cb"
      "b4e1edf21f6cb4fb7492782fe76c30197d54ec1d0a7329cbcb7be607a2017d79b3462b"
      "eb25ead50e33a3dc0f58a1614fed4151a5ad8661d744d9d4bc8fe9304a443d7fe82367"
      "1ce6abe71bb206a38a73f72e8143e4251885159b42784f75",
      /*.dq_hex_str=*/
      "367023116147e807e936bb466cbbbbd5662bf59f617af9beba3a8a60f04dbb26cf0d72"
      "000e7c63bd55a389969c0e807caa24964fc8c304adf95e20613adb7e6b08ddbb732a47"
      "fd91ab0ead83a99eac57b74a235edd6062a5845b62b1fc16f5ae130c16fafff25355b1"
      "096b0379e3a45569e05ab068c267ff358ac3ad55553f99",
      /*.coefficient_hex_str=*/
      "3a47030f3e868a1457f0290ae5e8e1a95fef23f9b8d90b20d8e75d138c94bc01e9922d"
      "60126a8af6c7142ebb32ced086b52cf1fa5dd389bce61bf6c66ec4c9d47cd08a8b5aad"
      "7d9f48202003cc19bdce05d1e41b568e60c43aec44a23031282bd46ac47ea77ddf2b8a"
      "303a784e27c73f9e0dd5b5f93e7be71361c2db675130d4",
      /*.public_pem=*/
      R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAZ+qQOMJLBjysYUayZ5
NJnMipOYUghZa5cArNTlGlgEEzFsxazFtJnUeBQhupsNivda5WthedWn/CCY8vxN
NmpqQWaxXyJU2xyzzl3Uq4C9i9Wttd80tgLDGdTQBCmcBuXiQ3/WJuKEwp7redGC
C4MLcGBy76L9HIiY0eqvOfufVM52ceorVRKkKQ0+xYu0Fjmhm+ZjCxwnBZuaMlBb
68b0KzAfn7LPK2JMG2WYcCu+rtOLX9mUHWYf9q3KZf+yUdHzFLztCGH6MOxnbiEp
5ay6A6bLdZT5PGDO+bKu7kXtxqrdMfhB7h83/WPM/zzruwGKPWMbPUmKeTSHBLtB
nwIDAQAB
-----END PUBLIC KEY-----)",
      /*.private_pem=*/
      R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Bn6pA4wksGPK
xhRrJnk0mcyKk5hSCFlrlwCs1OUaWAQTMWzFrMW0mdR4FCG6mw2K91rla2F51af8
IJjy/E02ampBZrFfIlTbHLPOXdSrgL2L1a213zS2AsMZ1NAEKZwG5eJDf9Ym4oTC
nut50YILgwtwYHLvov0ciJjR6q85+59UznZx6itVEqQpDT7Fi7QWOaGb5mMLHCcF
m5oyUFvrxvQrMB+fss8rYkwbZZhwK76u04tf2ZQdZh/2rcpl/7JR0fMUvO0IYfow
7GduISnlrLoDpst1lPk8YM75sq7uRe3Gqt0x+EHuHzf9Y8z/POu7AYo9Yxs9SYp5
NIcEu0GfAgMBAAECggEAcYsagcX6o01BdfoX6nzZRMJ7mlN28FLKbQZLChOmJjpw
e4alQNoMqfsbK0g89gscKoclBNXLj19OihrFQjbKCcpJUCVLhz+cLpUun7hZ7RdZ
X1AyDloz4pXYa4jv9ROLfT7lXA2erOytbzm4yV+TQJBqH/qebcfnQYvbfShTmJcp
fH2lNYhn5g3+jHb79aakwGTg9q8b88lkDL7gB66jvoEBe3JtCItplXuET5UfrDI/
8+ef1n2vMqPc6GIyCrD0p4JV90D3OBOWq41V+AwbOKFJ8kGKJ0d5W0SxQJL6F9IV
rg4zx4mXRxq5cWKLiXd2qAu97n7d9g7KbOy6UPMigQKBgQDj8VJGeEn0wth/WmUG
RTh4t1R5lrFAZ5ZuM2OZ4r5qjC6o8GUlHwXovc3kcz1whFI0MvOq1rdZkO+tvtvO
kcsJfOK4Xfoi/TyhKoYZjXbTEAlTE1HwckaTfNex2B02dfiv11nRJ57bEwbhL3V7
rzaOJl+0KXdbG00W2Ip7AJ8AxwKBgQDTK1fz0p90HDPM+V2YuTtO/VavD5vJj5CJ
2HYezM9l4Lp/7r+++PzjuzikpflhTUeijxNyOFGKtH8KEpEtyVGx1UBjK8VwM4sX
7k+GZ2e3upisagV/GisnEB7lhOnoLUqD8x7xTRHx2RBdw44wUqUGmC/zZ552DHrR
hvNhKEyQaQKBgQDFNr+WlPB3wjUKSq1pdW5ck1GVOVn2fSlcAz5DoDhbexnLtOHt
8h9stPt0kngv52wwGX1U7B0KcynLy3vmB6IBfXmzRivrJerVDjOj3A9YoWFP7UFR
pa2GYddE2dS8j+kwSkQ9f+gjZxzmq+cbsgajinP3LoFD5CUYhRWbQnhPdQKBgDZw
IxFhR+gH6Ta7Rmy7u9VmK/WfYXr5vro6imDwTbsmzw1yAA58Y71Vo4mWnA6AfKok
lk/IwwSt+V4gYTrbfmsI3btzKkf9kasOrYOpnqxXt0ojXt1gYqWEW2Kx/Bb1rhMM
Fvr/8lNVsQlrA3njpFVp4FqwaMJn/zWKw61VVT+ZAoGAOkcDDz6GihRX8CkK5ejh
qV/vI/m42Qsg2OddE4yUvAHpki1gEmqK9scULrsyztCGtSzx+l3TibzmG/bGbsTJ
1HzQiotarX2fSCAgA8wZvc4F0eQbVo5gxDrsRKIwMSgr1GrEfqd93yuKMDp4TifH
P54N1bX5PnvnE2HC22dRMNQ=
-----END PRIVATE KEY-----)"};
  return kTestVector;
}

class PemParserRsaTest : public Test {
 public:
  void SetUp() override {
    const RsaKeyTestVector& test_vector = GetRsaKeyTestVector();
    pem_rsa_pub_key_ = std::string(test_vector.public_pem);
    pem_rsa_prv_key_ = std::string(test_vector.private_pem);

    internal::RsaPrivateKey key;
    key.n = test::HexDecodeOrDie(test_vector.modulus_hex_str);
    key.e = test::HexDecodeOrDie(test_vector.public_exponent_hex_str);
    key.d = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.private_exponent_hex_str));
    key.p = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.p_hex_str));
    key.q = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.q_hex_str));
    key.dp = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.dp_hex_str));
    key.dq = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.dq_hex_str));
    key.crt = util::SecretDataFromStringView(
        test::HexDecodeOrDie(test_vector.coefficient_hex_str));

    absl::StatusOr<internal::SslUniquePtr<RSA>> rsa =
        internal::RsaPrivateKeyToRsa(key);
    ASSERT_THAT(rsa, IsOk());
    rsa_ = *std::move(rsa);
  }

  // Utility function that sets expectations to test that `bn_str` equals `bn`.
  void ExpectBnEqual(absl::string_view bn_str, const BIGNUM *bn) {
    absl::StatusOr<std::string> expected_bn_str =
        internal::BignumToString(bn, BN_num_bytes(bn));
    ASSERT_THAT(expected_bn_str, IsOk());
    EXPECT_EQ(bn_str, *expected_bn_str);
  }

 protected:
  // PEM encoded 2048 bit RSA key pair.
  std::string pem_rsa_pub_key_;
  std::string pem_rsa_prv_key_;
  // Holds the RSA object.
  internal::SslUniquePtr<RSA> rsa_;
};

// Corrupts `container` by modifying one the elements in the middle.
template <class ContainerType>
void Corrupt(ContainerType *container) {
  if (container->empty()) {
    return;
  }
  std::vector<char> corrupted(container->begin(), container->end());
  size_t pos = corrupted.size() / 2;
  corrupted[pos] ^= 1;
  container->assign(corrupted.begin(), corrupted.end());
}

// Test we can correctly parse an RSA public key.
TEST_F(PemParserRsaTest, ReadRsaPublicKey) {
  auto key = PemParser::ParseRsaPublicKey(
      absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()));
  ASSERT_THAT(key, IsOk()) << internal::GetSslErrors();

  // Verify exponent and modulus are correctly set.
  const BIGNUM *e_bn, *n_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, nullptr);
  ExpectBnEqual((*key)->e, e_bn);
  ExpectBnEqual((*key)->n, n_bn);
}

// Test we can correctly parse an RSA private key.
TEST_F(PemParserRsaTest, ReadRsaPrivatekey) {
  auto key_statusor = PemParser::ParseRsaPrivateKey(
      absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()));
  ASSERT_THAT(key_statusor, IsOk()) << internal::GetSslErrors();

  // Verify exponents and modulus.
  auto key = *std::move(key_statusor);
  const BIGNUM *e_bn, *n_bn, *d_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, &d_bn);
  ExpectBnEqual(key->e, e_bn);
  ExpectBnEqual(key->n, n_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->d), d_bn);
  // Verify private key factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa_.get(), &p_bn, &q_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->p), p_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->q), q_bn);
  // Verify CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa_.get(), &dp_bn, &dq_bn, &crt_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->dp), dp_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->dq), dq_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->crt), crt_bn);
}

using ParametrizedPemParserRsaTest = TestWithParam<RsaKeyTestVector>;

TEST_P(ParametrizedPemParserRsaTest, WriteRsaPrivateKey) {
  RsaKeyTestVector test_vector = GetParam();
  internal::RsaPrivateKey key;
  key.n = test::HexDecodeOrDie(test_vector.modulus_hex_str);
  key.e = test::HexDecodeOrDie(test_vector.public_exponent_hex_str);

  key.d = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.private_exponent_hex_str));
  key.p = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.p_hex_str));
  key.q = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.q_hex_str));
  key.dp = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.dp_hex_str));
  key.dq = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.dq_hex_str));
  key.crt = util::SecretDataFromStringView(
      test::HexDecodeOrDie(test_vector.coefficient_hex_str));

  absl::StatusOr<std::string> pem_result = PemParser::WriteRsaPrivateKey(key);
  EXPECT_THAT(pem_result, IsOk()) << internal::GetSslErrors();
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_result), test_vector.private_pem);
}

TEST_P(ParametrizedPemParserRsaTest, WriteRsaPublicKey) {
  RsaKeyTestVector test_vector = GetParam();
  internal::RsaPublicKey key;
  key.n = test::HexDecodeOrDie(test_vector.modulus_hex_str);
  key.e = test::HexDecodeOrDie(test_vector.public_exponent_hex_str);

  auto pem_result = PemParser::WriteRsaPublicKey(key);
  EXPECT_THAT(pem_result, IsOk());
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_result), test_vector.public_pem);
}

INSTANTIATE_TEST_SUITE_P(ParametrizedPemParserRsaTests,
                         ParametrizedPemParserRsaTest,
                         Values(GetRsaKeyTestVector()));

TEST_F(PemParserRsaTest, ReadRsaPublicKeyInvalid) {
  Corrupt(&pem_rsa_pub_key_);
  EXPECT_THAT(
      PemParser::ParseRsaPrivateKey(
          absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()))
          .status(),
      Not(IsOk()));
}

TEST_F(PemParserRsaTest, ReadRsaPrivateKeyInvalid) {
  Corrupt(&pem_rsa_prv_key_);
  EXPECT_THAT(
      PemParser::ParseRsaPrivateKey(
          absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()))
          .status(),
      Not(IsOk()));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
