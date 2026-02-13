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

#include "tink/signature/internal/testing/rsa_ssa_pss_test_vectors.h"

#include <string>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::HexDecodeOrDie;

RsaSsaPssPrivateKey PrivateKeyFor2048BitParameters(
    const RsaSsaPssParameters& parameters, absl::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-TEkod"
      "hWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_LYywlAGZ21"
      "WSdS_PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
      "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15_aX"
      "rk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXVrx-W"
      "E-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_OrADAYtAJs-M3JxCL"
      "fNgqh56HDnETTQhH3rCT5T3yJws",
      &p));
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coS"
      "KB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7e"
      "YTB7LbAHRK9GqocDE5B0f808I4s",
      &q));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQ"
      "Vy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jah"
      "lI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDms"
      "XOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8"
      "C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
      &d));
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDt"
      "t6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-"
      "vz2pYhEAeYrhttWtxVqLCRViD6c",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN"
      "06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6Feiaf"
      "WYY63TmmEAu_lRFCOJ3xDea-ots",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ5"
      "7_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9"
      "-2lNx_76aBZoOUu9HCJ-UsfSOI8",
      &q_inverse));

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
                                 id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

  RestrictedData p_data(p, InsecureSecretKeyAccess::Get());
  RestrictedData q_data(q, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);

  ABSL_CHECK_OK(d_data.status());
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  absl::StatusOr<SecretData> q_inverse_data =
      ParseBigIntToFixedLength(q_inverse, p.size());
  ABSL_CHECK_OK(q_inverse_data.status());

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(p_data)
          .SetPrimeQ(q_data)
          .SetPrimeExponentP(RestrictedData(*prime_exponent_p_data,
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(*prime_exponent_q_data,
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(
              RestrictedData(*d_data, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(
              RestrictedData(*q_inverse_data, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return *private_key;
}

RsaSsaPssPrivateKey PrivateKeyFor4096BitParameters(
    const RsaSsaPssParameters& parameters, absl::optional<int> id_requirement) {
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "QfFSeY4zl5LKG1MstcHg6IfBjyQ36inrbjSBMmk7_nPSnWo61B2LqOHr90EWgB"
      "lj03Q7IDrDymiLb-l9GvbMsRGmM4eDCKlPf5_6vtpTfN6dcrR2-KD9shaQgMVlHdgaX9a4Re"
      "lBmq3dqaKVob0-sfsEBkyrbCapIENUp8ECrERzJUP_vTtUKlYR3WnWRXlWmo-bYN5FPZrh2I"
      "0ZWLSF8EK9__ssfBxVO9DZgZwFd-k7vSkgbisjUN6LBiVDEEF2kY1AeBIzMtvrDlkskEXPUi"
      "m2qnTS6f15h7ErZfvwJYqTPR3dQL-yqzRdYTBSNiGDrKdhCINL5FLI8NYQqifPF4hjPPlUVB"
      "CBoblOeSUnokh7l5VyTYShfS-Y24HjjUiZWkXnNWsS0rubRYV69rq79GC45EwAvwQRPhGjYE"
      "QpS3BAzfdodjSVe_1_scCVVi7GpmhrEqz-ZJE3BYi39ioGRddlGIMmMt_ddYpHNgt16qfLBG"
      "jJU2rveyxXm2zPZz-W-lJC8AjH8RqzFYikec2LNZ49xMKiBAijpghSCoVCO_kTaesc6crJ12"
      "5AL5T5df_C65JeXoCQsbbvQRdqQs4TG9uObkY8OWZ1VHjhUFb1frplDQvc4bUqYFgQxGhrDF"
      "AbwKBECyUwqh0hJnDtQpFFcvhJj6AILVoLlVqNeWIK3iE",
      &d));
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AK9mcI3PaEhMPR2ICXxCsK0lek917W01OVK24Q6_eMKVJkzVKhf2muYn2B1Pkx"
      "_yvdWr7g0B1tjNSN66-APH7osa9F1x6WnzY16d2WY3xvidHxHMFol1sPa-xGKu94uFBp4rHq"
      "rj7nYBJX4QmHzLG95QANhJPzC4P9M-lrVSyCVlHr2732NZpjoFN8dZtvNvNI_ndUb4fTgozm"
      "xbaRKGKawTjocP1DAtOzwwuOKPZMWwI3nFEEDJqkhFh2uiINPWYtcs-onHXeKLpCJUwCXC4b"
      "EmgPErChOO3kvlZF6K2o8uoNBPkhnBogq7tl8gxjnJWK5AdN2vZflmIwKuQaWB-12d341-5o"
      "mqm-V9roqf7WpObLpkX1VeLeK9V96dnUl864bap8RXvJlrQ-OMCBNax3YmtqMHWjafXe1tNa"
      "vvEA8zi8dOchwyyUQ5xaPM_taf29AJA6F8xbeHFRsAMX8piBOZYNZUm7SHu8tJOrAXmyDldC"
      "Ieob2O4MRzMwfRgvQS_NAQNwPMuOBrpRr3b4slV6CfXsk4cWTb3gs7ZXeSQFbJVmhaMDSjOF"
      "UzXxs75J4Ud639loa8jF0j7f5kInzR1t-UYj7YajigirKPaXnI1OXxn0ZkBIRln0pVIbQFX5"
      "YJ96K9-YOpJnBNgYY_PNcvfl5SD87vYNOQxsbeIQIE-EkF",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "5ADsrLVcQaplxzu5JfAVsqNI0KZUGEIaqwNF0onUStKZb3yCcnukEgdOaLIV0mpTbRLNj5gH"
      "TlePdt9Jim0lE8s7ZwaLCvCNEH8Swbw6p7Ff_mV73_"
      "zH7yLoyFjfEZfksAFizx0HRouXfKw61GAi8J7J6gnQjudFiPAOV7HGOX3Ps4jbxxbtN2-"
      "WNuT4sCAGbKCwyW4_b6ftPnwOX5IP7wFPl6IYUMW7vqH--bJNcHX_NOgCoErYLmgzs4X_"
      "tnvO4uPHu_PjTEfooPtGSS9zCb3nB-FgRm0dgXCpSFqMTW8PmcJwZwI2Gq5MvM-"
      "VblE3YCzGb78OT6nukiQf1oA_SQ",
      &p));
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "xO_5zkhFNG9vHtXJ_Tp1_ZGbYDB1pGXDLVAbdgB2iND8-"
      "EgI0fT6ZMephp41lGNroqeIUqppiKaB1xxbZSEYYpldCEeHK5xn4ATQ208sWR3tGF6Bysfmx"
      "sc5wO1YJIbByd71bOznhXKEiEaY5Lkdi4tQP6wHQ2AzOby82ycX-"
      "oi3jnzHovgYT3sedGct1IkEVo2QR0skZc3V9u0kgaB0o3Vo5zkpp9OL6rYMAcR7dKZPMU9YP"
      "o0n6OjRokT19dFDToFTBQm1lfBoLgUKlxkqd7Y9KCVzwCWpA66VwUuuwnx-cb-9zu2tL-"
      "nD3MLFpolB25g_JNsz3-zMGPbTqUlv3Q",
      &q));
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "WQVTYwtcffb9zhAvdfSLRDgkkfKfGumUZ_jbJhzSWnRnm_PNKs3DfZaEsrP1eT"
      "YyZH_W6p29HIVrako7-GQs-dF72_neB-Nr8Gjs9d98N0U16anN9-JGXcQPh0nLrp7TlzSzU5"
      "JN6OlPuEm2nnz6p2AYDdzPJTx_FbxEnVC3yHKqybpBtTXqYJ6c08oKnxmh6H_FBqCY_Atgwe"
      "jF4-Kvfe3RGa8cN008xG2TlAJd4e7wOcPsYpFWXqgop4tGEAW-_S9aKLRMptfcqB3zj1eLXt"
      "5aeeUxJc4smwFV1v4jkYgvWyVjpZRjc39iTsXt3iivqklRIQhDmi8LCtw34hQooQ",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "jdHvCCE9TQxubjsw8Z4W-BrSVIuxPElYK5qDnA-rTM2LTtS5HVGYu9iY-"
      "WuXVBvgmEqjPjygMRsPZ7RxELurjt24hEzWR46js0xkh3pVinulkSYFu90HEODJc2i4T92HU"
      "nOwM9fKxmv4ixaj5hp071fM231r4ZY2bX7AVeWqO-"
      "4WmZK8RVz6TMpx3QuskmB1cksRunWfaXy4d9DAuGSvekMD33dnywbpvIWK0f8HlLJrVyw3dR"
      "w7wFthE8UrhvFC0hcJjRg33xk4POO-g59I2Nqw4edOmvHD6_XevEtfN4llmU6mRo0caeOi-"
      "6h7o3k2pwfVeRouGjSxqcyeEkvjNQ",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "vqDKQjTsH-0tzkwRRvABl5zx-sGRwi_B2WdtyGai_"
      "2rmwGcjvEm3TsEmXKubyn9da45uWbHpCDhxwrATWO3cJ3fontf3YP0gnB9qDK2Z5PjCau4zt"
      "Bu7ODuIZ5fhEngIuS-wllFKHwW-6b6ozATKfKlUkwHn5TDxj_oJ3-"
      "cxl5Irukmzx7CtLssNjs4OevPGQnXFEJelVu-"
      "wHSYpw6aEz18PpDWqSPCYGfgxgETYPWKb9LZhu3YCJKMDExfozy7w3yFdwS7SjN5N-"
      "xnLUc4X0e5NF050SHg_5m_NCprBIsXkdOTzb_4X7KJM-"
      "G2VyoI0VsKzSkoZ5kgVlD1l8rmSfw",
      &q_inverse));
  RestrictedData p_data(p, InsecureSecretKeyAccess::Get());
  RestrictedData q_data(q, InsecureSecretKeyAccess::Get());

  absl::StatusOr<RestrictedData> d_data =
      RestrictedBigInteger(d, InsecureSecretKeyAccess::Get())
          .EncodeWithFixedSize((parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  absl::StatusOr<RestrictedData> prime_exponent_p_data =
      RestrictedBigInteger(prime_exponent_p, InsecureSecretKeyAccess::Get())
          .EncodeWithFixedSize(p.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  absl::StatusOr<RestrictedData> prime_exponent_q_data =
      RestrictedBigInteger(prime_exponent_q, InsecureSecretKeyAccess::Get())
          .EncodeWithFixedSize(q.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  absl::StatusOr<RestrictedData> q_inverse_data =
      RestrictedBigInteger(q_inverse, InsecureSecretKeyAccess::Get())
          .EncodeWithFixedSize(p.size());
  ABSL_CHECK_OK(q_inverse_data.status());

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
                                 id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(p_data)
          .SetPrimeQ(q_data)
          .SetPrimeExponentP(*prime_exponent_p_data)
          .SetPrimeExponentQ(*prime_exponent_q_data)
          .SetPrivateExponent(*d_data)
          .SetCrtCoefficient(*q_inverse_data)
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return *private_key;
}

// SHA256
SignatureTestVector CreateTestVector0() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0"
          "c39e9647fd27c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583"
          "058296019fe968e92bcf35f38cb85a32c2107a76790a95a715440da281d026172b8b"
          "6e043af417852988441dac5ea888c849668bdcbb58f5c34ebe9ab5d16f7fa6cff32e"
          "9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d347c6f92996dcb24f99701"
          "d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e9920c2668c"
          "8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba"
          "8dc713941f92a7a4f082693a2f79ff8198d6"),
      HexDecodeOrDie("aa"));
}

// SHA512
SignatureTestVector CreateTestVector1() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a230e"
          "c189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15d67b858782afa5f9c6"
          "7d3880275d67cd98c40064adf08d9a58f0badb5c47b88a06ed81a23ffb131380c2f3"
          "bbc16a9290d13d31df54e2061b2f0acb3629a3693f03b3f2004b451de3e1ae286165"
          "4d145a5723f102f65533598aa5bc8e40b67190386a45fe99bf17c4610b2edf253887"
          "8989cacffd57b4c27c82ab72d95f380e50f0282423d759a6d06241cd88a817e3c967"
          "ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe01edadf0382c8ab2a897580c1cdf"
          "4e412032a083d1e5d47a625a38aac8c552e1"),
      HexDecodeOrDie("aa"));
}

// Variant: TINK
SignatureTestVector CreateTestVector2() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          "0199887766"
          "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a230e"
          "c189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15d67b858782afa5f9c6"
          "7d3880275d67cd98c40064adf08d9a58f0badb5c47b88a06ed81a23ffb131380c2f3"
          "bbc16a9290d13d31df54e2061b2f0acb3629a3693f03b3f2004b451de3e1ae286165"
          "4d145a5723f102f65533598aa5bc8e40b67190386a45fe99bf17c4610b2edf253887"
          "8989cacffd57b4c27c82ab72d95f380e50f0282423d759a6d06241cd88a817e3c967"
          "ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe01edadf0382c8ab2a897580c1cdf"
          "4e412032a083d1e5d47a625a38aac8c552e1"),
      HexDecodeOrDie("aa"));
}

// Variant: CRUNCHY
SignatureTestVector CreateTestVector3() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetVariant(RsaSsaPssParameters::Variant::kCrunchy)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          "0099887766"
          "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a230e"
          "c189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15d67b858782afa5f9c6"
          "7d3880275d67cd98c40064adf08d9a58f0badb5c47b88a06ed81a23ffb131380c2f3"
          "bbc16a9290d13d31df54e2061b2f0acb3629a3693f03b3f2004b451de3e1ae286165"
          "4d145a5723f102f65533598aa5bc8e40b67190386a45fe99bf17c4610b2edf253887"
          "8989cacffd57b4c27c82ab72d95f380e50f0282423d759a6d06241cd88a817e3c967"
          "ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe01edadf0382c8ab2a897580c1cdf"
          "4e412032a083d1e5d47a625a38aac8c552e1"),
      HexDecodeOrDie("aa"));
}

// Variant: LEGACY
SignatureTestVector CreateTestVector4() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kLegacy)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          "0099887766"
          "433065815d23c7beff4780228b0e6212d7cedd6998c5528bd5b0a3ce90066a4a1f76"
          "c703745c23b4f7d92a5c84871dc9e6b2800d2bebd3d651afa86b1eb68924bacabc06"
          "99358417319f5f9f7b326e636457c6098676f61c549b25c40975ee5cefa4c3c2b7d5"
          "d81efa0a78e4c777908762a0348022d425aafcdc4f6ada902d359758ad75ae8988eb"
          "522ea11771c9d84fc9ffe6f3b317872335b1d4af5f60e40e1a0d2588cb6640383b5b"
          "193f094754c21250485eb9430b056bab0d781ba261bd6cf80ad520402b83bc30a81d"
          "9ce38b7de9844d7d1310696de099dbf2b642cfca8edb6b098c71d50710668870f3e4"
          "7b115ecf4a0933573c92027d737647daa9f8"),
      HexDecodeOrDie("aa"));
}

// SaltLengthBytes: 64
SignatureTestVector CreateTestVector5() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(64)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "aa5310c40c83878e0116ccc09efda3be6a88c667c797e61b6831e109fd6b5fbed9df"
          "08cf05711d79cb384164fc5ddfb0de10a5110053c2b073449603bb11994fc0847d92"
          "9806d5034e24db0662df5c0963fbac1d214842c4de1d7f4bfb741d8a2866e24819e8"
          "073042d17bccef92bbcdc6b34ca052486d60d12e9d992cebaaca5df2d7ea31c08af4"
          "d35338cdaa460a0ee568ff2bdaab1d72d6a8360713d98a0923ae929cff9950fd48bf"
          "0fa05e4324f4f9561defbb8e2c4854122394dd55bda740d57064956255e36c6c1cc1"
          "970947d630121df570ba577957dd23116e9bf4c2c826ec4b52223735dd0c35516548"
          "5ff6652656aa471a190c7f40e26c85440fc8"),
      HexDecodeOrDie("aa"));
}

// ModulusSize: 4096 bits
SignatureTestVector Create4096BitTestVector() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor4096BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "20c933ec5b1c7862d3695e4e98ce4494fb9225ffcca5cb6ff165790c856a7600092b"
          "8dc57c1e551fc8a85b6e0731f4e6b148c9b2b1ab72f8ea528591fa2cfc35a1d893d0"
          "0aabff2d66471bcfa84cafa033d33ca9964c13ee316ddfdde2d1766272d60440f5df"
          "0eba22f419f2b95c2decf3621f0c3cb311b7f72bf2ca740414b31f74d3dd042abd00"
          "5a1adc9aa4e57b65ef813476d7294aa516f04f96211dcc74497fd7f876997595ef1d"
          "3e9be241c0455acda0d004ecfbd66bba5b98fcec6d8bba4ede1d88ab585e42214216"
          "7ac6fc096ddf389598f35a7b361f1946212e71b0d6f5ae5ae594bd4bc4ed52a8aa21"
          "607d845f2f9b921cc05edd12a8ecdb40d1265c4e038855dbcf895c9ce0012f62194e"
          "afa3aec3ae38fcf9922e80b3f123bfa6f5eea4d90036057eeabf3219fefd6bb92054"
          "89a9fb55e1ff280ab946350ca3dd7cd328c033a4e5756bffaa83f94767d02dcd2ba0"
          "c78af4e4dc51fae1125f683278c659fb9e2b269131af86410599d798e0d626477fb9"
          "4af9be8e7c95f12467434b12fb415cea98c4eb05d879ef1e7eebf7926868f21d9e51"
          "c184bdc679c8aceda400bb4edc29c029b4b939b2ac43d712ef4b68a058f5f45ac700"
          "22abc5fec9389333a8b67a54b4a994f3ca7fdf14c73b5b130220fcc2607b27bdfa2b"
          "37e115bc8ccfe2489f51642f8556b0240ad86f7620d3e7664f76ac671da08e92b76f"
          "512b"),
      HexDecodeOrDie("aa"));
}

// Sha384
SignatureTestVector CreateTestVector6() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(32)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "8c87ec23317b97c5d5e3692da3aa7037c183d757d0aa79ed1a2ccc46cde8397e2a8b"
          "231057034b2435813587314335bf308f9c930682e7575ec54968fdf15d9a689230ee"
          "2822338a97f08af3ce85b81f1c482617a2f3316b78b59ec3243541eb4e32bc3a33e2"
          "0729f4019085dda89f7a6c4584ab9f4288755e65117f3f1dca298ef9605804ee69a8"
          "8bc7d7addb99b9dbee9f858d1f7df01f0b12fa9a9534bdeaf7f197c1cafcb0853f32"
          "bfed7cb9495f073fcaa2d73eab5f9398b07300dbc9b80dbff248106e6c8a52e564fd"
          "9de73e0122f576e5fa3c4bdb477663b616372568492b4f00b6261800b132a04a3dc7"
          "35e44fc4ce9a72e3afaca5a0d50ea77388c9"),
      HexDecodeOrDie("aa"));
}

// SaltLength: 0
SignatureTestVector CreateTestVector7() {
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .SetSaltLengthInBytes(0)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPssPrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "5bfef53336a5148a2f880e28c92c71fa0523707390d075d7608a8eeab44cff516694"
          "6850f5818b00e4876922bf7cc0fedfdc1f8e265200c4c10e41686f62f8a621b8ca27"
          "71106deb28fa9b0ec2b2687f106b8f68695dddc0b80dc15bec32e7ad2de73edb2789"
          "a8222866521230f2795b6c74de777050f02a0315776855f4bb1e063c93ef8d1c4a91"
          "abe393017b0cfa09548f6f5bfd565d02bdce2116ffca232ede6f4e869aac226f703a"
          "e0ef739fe926f0f15f916a7fa17b407118d9a54353794835c224fa8c7b9213771526"
          "a7acb7575ddbd4ea3aaad6c827a5d1378773a4556763ed1442fddc76e29585c9d199"
          "2d42a8b730e744e44f3bfe5ddddc47b5d728"),
      HexDecodeOrDie("aa"));
}

}  // namespace

std::vector<SignatureTestVector> CreateRsaSsaPssTestVectors() {
  std::vector<SignatureTestVector> test_vectors = {
      CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
      CreateTestVector3(), CreateTestVector4(), CreateTestVector5(),
      CreateTestVector6(), CreateTestVector7()};

  if (!internal::IsFipsModeEnabled()) {
    test_vectors.push_back(Create4096BitTestVector());
  }
  return test_vectors;
}
}  // namespace internal
}  // namespace tink
}  // namespace crypto
