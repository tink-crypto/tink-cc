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

#include "tink/signature/internal/testing/rsa_ssa_pkcs1_test_vectors.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));

using ::crypto::tink::test::HexDecodeOrDie;

RsaSsaPkcs1PrivateKey PrivateKeyFor2048BitParameters(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
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
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B_coS"
      "KB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_ym2QnkwsUX7e"
      "YTB7LbAHRK9GqocDE5B0f808I4s",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQ"
      "Vy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jah"
      "lI7LyckrpTmrM8dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDms"
      "XOfUENOyMqADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8"
      "C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ",
      &d));
  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDt"
      "t6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-"
      "vz2pYhEAeYrhttWtxVqLCRViD6c",
      &prime_exponent_p));
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p_data.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN"
      "06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6Feiaf"
      "WYY63TmmEAu_lRFCOJ3xDea-ots",
      &prime_exponent_q));
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q_data.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-Py4dQ5"
      "7_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5gry7ajdYy9"
      "-2lNx_76aBZoOUu9HCJ-UsfSOI8",
      &q_inverse));
  absl::StatusOr<SecretData> q_inverse_data =
      ParseBigIntToFixedLength(q_inverse, p_data.size());
  ABSL_CHECK_OK(q_inverse_data.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_2048_sig_gen_test.json
RsaSsaPkcs1PrivateKey PrivateKeyFor2048BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "orRRoH0KpfluRVZxUTVQUUqKW0YuvvcXCU-h_ugiJOY3-XRtP3yv0xh42AMltu9aFwD2WQO0"
      "aUKeidbqyIRQl7WrOTGJ25JRLtincRoSU_rNIPecFegkfz0-QuRuSMmOJUov6XZTE6A-_48X"
      "4aApOXofomqNzib0kO2BKZYV2YFMItphBCjgnH2WWFlCZvXAIdD87KCNlFoSvoLeTR7Oa0wD"
      "FFtdNJXU7VQR64eNrwX9evw-Ca2g8RJkIvWQl1oZaYFvSGmLy7obTZyuedRg2Pn4Xnl1AF2b"
      "wixOWsD3waRdElaaYoB9O5oC5aUw53MGb0U9H1tMLpz3ggKD90K51Q",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "3EMQUPeC6JT7UkgkfZjLfVi40eJPO1XQQcVuTeCGsNW7AovaQu610jTVaB5YCdQV5qKJrUz7"
      "94-Xj2w1gU9Q7r_xxbgKafeI6B5rq13ap4Np1lnRQ-xvF-eYE6V1z62cVpFWuQET4ukRCtnn"
      "tIock0im5lMyEZEpDqNs-zpbGPE",
      &p));
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "vRqB55d_mJgSInOuMiK1mOpfsZ606rw4MIpeMhlmA7LlAP-3n1uIaBZhHevEcvrEVUQHC-sF"
      "fJQTeKaGivO3oD0_mIDsR9XgiblPveVCq6mujXLFcIjXq_WxMfOQmPe8Fg-QU2q8lJL9Tgbz"
      "7XKZ1Ll7sDZ3IH2VZp8UDPvCDyU",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "difu81Z7KicmjlIFPs0xw6cXLMud3O6BmzBqWzxmt1c8pPqI78bzxKAL-grnE59kVDpNrD0F"
      "gj9v9HfPzshP4qx6aLFyBLOQIy4RAxDE6JnE58EJZ9tKzeBC278Z2-ALS0dB3hAgqqr_tQVM"
      "eXyfE299k6w_yMr_ZlQkLXgh6-5Re_U39ENmoP3UWuBbmQnC5swe2Sge_0OZ92yWuWIz7Cmu"
      "C78NdSsjT8GXOJ9RBQqhrNAcB0w6yPvbnqi2UalZlejbStXEO2yGc-WhJufulLjf9MWvwBJZ"
      "vI2naVC65vi65xX1CYWw1vZtBMb-87cAcg7s3N8XG7ex7L5yicRnwQ",
      &d));
  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "qUtSiyjykVmRIdkZUv_Rx_IdfBR52Z1HiIX7Fhhw7hIYvwhHJhLb5Ul-jZxlBojgnHhpYa4-"
      "LDVNxIrjRRR1nEwjxFiEiJYdwGtBTmHA4ef7vSkj0xUy_iifltoiBxHljBQBmAjgBBQnaTO7"
      "B-TvubSps3ZWkXIFIJ8z8JUV18E",
      &prime_exponent_p));
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p_data.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "OvDnKpM67wn_JQPfeLr-1THAL_GivEN8VAzcvUrTVDXPURdjWWVDSAYpsRTKf3gP9--jLqDL"
      "bgANbZ6h8u9x_Zz5lIQioWVVfjfnVe3-cNkLkgUC60eLyYpj94jOOg-FbW7eclGjg7-o-kgK"
      "gaklr3s8xTjEurjJ91l_-2gBHY0",
      &prime_exponent_q));
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q_data.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "JkD7-8_vsWPueoe2SDpm7kH5VtkPqKeTm_wELuCSSxt5k9BEX3WNUZM-hRecAyCwyWi0ipHD"
      "i1vpI-EJfAxWL4jUIpS2onWbr6VCinTxJwh05F9vzGDyFgLeXszRQ88xJB9ZIbWtOYP7VO8X"
      "vjsoU2flDJmcZyR7VS_kv86UX3s",
      &q_inverse));
  absl::StatusOr<SecretData> q_inverse_data =
      ParseBigIntToFixedLength(q_inverse, p_data.size());
  ABSL_CHECK_OK(q_inverse_data.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

RsaSsaPkcs1PrivateKey PrivateKeyFor3072BitParameters(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "ANyPeIBnLwz51jYXqKWL3ScaEJut2g-oJvlLinlVJrakmoBWTMq6ipSRqTWlPt6uHZp7VGPZ"
      "4u8-4M57_11LbIFHtcBzwvIgUV1THVWjZoem3jw0d1wvFRkawKdC1zQiKMjZEP5rvKQ5U5xI"
      "XevL0O4OS64xdQO4PO6BAKx7tFh0Z8vENzxL2i7t98QWMeUJIrWA9bzoHSSyCMq80tdfz-mf"
      "dbST3_xcm9mQ9_w78u_jkv7K428-TvRFbBtd6ZzHRRczqRC2g0th7CknTZhr43UsNQsToyfa"
      "vAjfz2VlSZrSboU0RmM-rbKXDKlbz2vwX_28KoBDeNdphacfBvkJefn-9xbDaqYlpFte7fUI"
      "JaU-nZQ1sjyqueXGTTj9OnZ-GFrXcn1uFfnpurL0GE1kh2lduaJpjGcrLoI0ENvvHZP-QMnT"
      "V-6fx3-EneETY_WDr4zPUYHKGuuUTEIlFstAHpUJI-S9iBQ5-hCTx3WCv-GsWZNnRwC2Q0M5"
      "4CRTFdhvyw",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "_sahC_xJtYoshQ6v69uZdkmpVXWgwXYxsBHLINejICMqgVua9gQNe_I9Jn5eBjBMM-BMhebU"
      "gUQvAQqXWLoINkpwA175npyY7rQxUFsq-2d50ckdDqL7CmXcOR557Np9Uv191pkjsl365EjK"
      "zoKeusprPIo8tkqBgAYUQ0iVd4wg1imxJbafQpRfZrZE84QLz6b842EHQlbFCGPsyiznVrSp"
      "-36ZPQ8fpIssxIW36qYUBfvvFQ51Y8IVCBF2feD5",
      &p));
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "3Z7BzubYqXGxZpAsRKTwLvN6YgU7QSiKHYc9OZy8nnvTBu2QZIfaL0m8HBgJwNTYgQbWh5UY"
      "7ZJf62aq1f88K4NGbFVO2XuWq-9Vs7AjFPUNA4WgodikauA-j86RtBISDwoQ3GgVcPpWS2hz"
      "us2Ze2FrK9dzP7cjreI7wQidoy5QlYNDbx40SLV5-yGyQGINIEWNCPD5lauswKOY8KtqZ8n1"
      "vPfgMvsdZo_mmNgDJ1ma4_3zqqqxm68XY5RDGUvj",
      &q));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "BQEgW9F7iNDWYm3Q_siYoP1_aPjd3MMU900WfEBJW5WKh-TtYyAuasaPT09LiOPsegfYV1en"
      "RYRot2aq2aQPdzN4VUCLKNFA51wuazYE6okHu9f46VeMJACuZF0o4t7vi_cY4pzxL8y5L--Y"
      "afQ67lvWrcIjhI0WnNbCfCdmZSdm_4GZOz4BWlU97O4P_cFiTzn42Wtu1dlQR8FXC1n6LrPW"
      "iN1eFKzJQHuAlPGLRpQkTrGtzWVdhz9X_5r25P7EcL4ja687IMIECrNg11nItOYYv4vU4Oxm"
      "mPG3LHFg7QUhyCtRdrYPtjUD0K4j9uL7emCTBbCvYhULkhrFP03omWZssB2wydi2UHUwFcG2"
      "5oLmvzggTln3QJw4CMDlPyVJNVQKOBqWPCwad8b5h_BqB6BXJobtIogtvILngjzsCApY1ysJ"
      "0AzB0kXPFY_0nMQFmdOvcZ3DAbSqf1sDYproU-naq-KE24bVxB0EARQ98rRZPvTjdHIJxSP1"
      "p_gPAtAR",
      &d));
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "8b-0DNVlc5cay162WwzSv0UCIo8s7KWkXDdmEVHL_bCgooIztgD-cn_WunHp8eFeTVMmCWCQ"
      "f-Ac4dYU6iILrMhRJUG3hmN9UfM1X9RCIq97Di7RHZRUtPcWUjSy6KYhiN_zye8hyhwW9wqD"
      "NhUHXKK5woZBOY_U9Y_PJlD3Uqpqdgy1hN2WnOyA4ctN_etr8au4BmGJK899wopeozCcis9_"
      "A56K9T8mfVF6NzfS3hqcoVj-8XH4vaHppvA7CRKx",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "Pjwq6NNi3JKU4txx0gUPfd_Z6lTVwwKDZq9nvhoJzeev5y4nclPELatjK_CELKaY9gLZk9GG"
      "4pBMZ2q5Zsb6Oq3uxNVgAyr1sOrRAljgQS5frTGFXm3cHjdC2leECzFX6OlGut5vxv5F5X87"
      "oKXECCXfVrx2HNptJpN1fEvTGNQUxSfLdBTjUdfEnYVk7TebwAhIBs7FCAbhyGcot80rYGIS"
      "pDJnv2lNZFPcyec_W3mKSaQzHSY6IiIVS12DSkNJ",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "GMyXHpGG-GwUTRQM6rvJriLJTo2FdTVvtqSgM5ke8hC6-jmkzRq_qZszL96eVpVa8XlFmnI2"
      "pwC3_R2ICTkG9hMK58qXQtntDVxj5qnptD302LJhwS0sL5FIvAZp8WW4uIGHnD7VjUps1aPx"
      "GT6avSeEYJwB-5CUx8giUyrXrsKgiu6eJjCVrQQmRVy1kljH_Tcxyone4xgA0ZHtcklyHCUm"
      "ZlDEbcv7rjBwYE0uAJkUouJpoBuvpb34u6McTztg",
      &q_inverse));

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

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

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(q, InsecureSecretKeyAccess::Get()))
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

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_sig_gen_test.json
RsaSsaPkcs1PrivateKey PrivateKeyFor3072BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "xv4jeSVmAjwmUofFrG9xVBwJlNEdBZ7mQDmG76IcJLUb2R2IYvnfeaTjKOPifIPfJgslqbQ0"
      "IK_8RLUejXUltvKcNypAUQRzIAdSemLtgvrHP0iSqA4JaCpBpYzTRwF_O-fYATNPktkyGq_V"
      "O1G_-r_HUs_Mrgse4Dva_55CjMHBF_GslrT-I_jCPmOBGGpm_VkokzmuVcS82tv_hKvapTIk"
      "DU4dKLLQSB2t07JGVXyo_hgJKBdzCznm7jeP_MhbGf_ckWqbmRprZtSpx7q19eejciEBFC56"
      "QQjBXVc7FSieB-RurqB7QsKry6Mw6ZVUtGVhZbtMDbK2OToH7KV1xRqTxOFb2w90eQlEfj7-"
      "NMZ8qJVLUw5WogobbYTUXtG806pY7AbxhO5YV6qoGeHMqaJvTijWuXfTORbbmJbSUtGvp2Li"
      "h8sNOEzHW_5T9Oki0C3QpIHAQuLTBrSzwYk3HldbJeAAWhZM9p3Ql25NW-R2gG6mvmCE5xq0"
      "9axcGxID",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "9eyhbg6DaWsO2ayKgSVF2rpV8gqWTE5jQ2BKfyvihg_On6FqHMkhIJOd64jf9oVQOD6thR-s"
      "B60bLoqbK7aVJdls6rt-6DzlDwjWSRB_RJoUUhpok_PzxcWnA7L8KL_P4mGk9_RQVYCA3q6q"
      "tlHHqa5YbB5_XFLNqT5AqskI5OM1eYT8EWr5y-lTm8eo07NRpz6lwkE9HaLgtEi0VGcKyon_"
      "5zsUAem4VU_D8j1skEYjJRodKZYsqbJtlzNFvExf",
      &p));
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "zyVEb1nPUSkZ3b_PotlnBJWtkrbyldYQMgV_nabb78RRCmI8K0elIgCCo7xCrxoUT5jJ7k_a"
      "5Bvg7FAczJSysGQBkQmbNVYRFg3rMn6KzgGLiYAl70cOQ3PsHZf2aeKY4dhFxlU8ClRsyxaN"
      "W1ENvmAY_U7Zo1Rfm9uBlo9KbXx5Dlw0cpqO-0lghvoTACSauLKPOJUde-4cEnrDxNC9WW7e"
      "4enRd4HbuCJ9e112zouLzgPF0zm5dXmBYQhIxVzd",
      &q));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "cqxrttmlcm5FS1QwxxElxumtX9QuHFoYqDQ-nYPXIhQ4ayMIwLjsXsZ1nc_NaiH4i4zq9GQD"
      "kj64asPRSoWS6V3gRi4UCFw_F9sAXcT6yHtKLR7eXPhR1XRchlGkQ4wKTXRq1y5BkgeWRyjD"
      "Ab83mgHAlOlpM3b3IRN9Pcdu5HyXkPvVkLfWqNYm4hsnfvF6Tk9-AXHBFG4ewyT6l_MNOhuu"
      "CPjV9uks_BIWZSOcQpFnNZ6WUENLKdIBUZA1at_uEvJbNBsI8St_7GN5WYr31cwk_n8A3h1H"
      "EzzjrYtr4cmoVOM_uVLhZKxt0qkFIYbuFE7n3ZhqjwOJHQ2iHteFFtzcKsic3dyLVEcx1m-d"
      "ib8XpQxtmHpZiwLJONw2UhuIHqmU5Mj7K6j9AB9zM11N0b2-F30wk884g2V8n_lE6PXJzeVI"
      "t8GwdBkpsNdJd-zaaU2UCu_Z0vx1Mj4LOhFLmf6vPiUY9RWNH9nZU6ogrxWOZ9J-LOLxjZf9"
      "AvNpmBl5",
      &d));
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "Y1ellnnSaAFRTGlAwg62ezcOhOn18PkxbAQ308t8hD9abm2cGei9sxUuk_kEz-bmkvHu0noK"
      "2kb5VgGz0SK-eT2tm90F1PbUaRBez8EUSDgdwVTdrfa8IMZJQ1tINYXWilJ7e5Z75S414L6a"
      "Q3Ahwc-l9HcVZ8wjPBzjrpnrN9r4vRAVa0vVgKPOnH05G9uyPmc2OpR0BcbIEsvT3MyLNWot"
      "r9DTsjohtoS0WOSrOFS82b4EzcnWXO6xCoUxxHDt",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "BNrav8FbGovcD1Zvh2GRCIp5hvbCuMBLoOCAHTHL9dKkE5o5zsnfFOzuIuhGp9P0peju0qcM"
      "ekws-VznT-QsS_YME1omSRm7TMkGuig9GJbwrkhSm0kPDIWrAwaMv-6Pprtq5zsYLSXNZvUg"
      "WwOLTurxqv4uG6Xel8iNQPoaxHYmYC_JCuaUc09E8-TojRhOiAWnVawpBL6P6d72t6YsyevP"
      "TXwtbJ-ehrJIPpvyLOUYYbu05z5zGk2-uod3LSk",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "IUofcxMOSLM2_gG5UIhezbNEPZPn6Mpi-w2pa9QjdZ2L5VLIvkTxOfvubsJLdfvwdE-sTaq_"
      "VIj-bDYA2bjpqSJIH8dKej1iJmLbjIUxjeSO6LcW8ZQp-1lJkNpwXr3372YT3Wv4hcFq1l6f"
      "5sKAOGvul2wl26_4-_abrtlRC-Xt7T-Q4LpKl-XIGiGJ8RRnB0Wrle3aIVvQX9x4kp-gz-iw"
      "HIPyrsk-OtGjNP2FqoeU6s-VWuXazUWyaHQfyhlc",
      &q_inverse));

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());

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

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(p, InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(q, InsecureSecretKeyAccess::Get()))
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

RsaSsaPkcs1PrivateKey PrivateKeyFor4096BitParameters(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
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
      "AOQA7Ky1XEGqZcc7uSXwFbKjSNCmVBhCGqsDRdKJ1ErSmW98gnJ7pBIHTmiyFd"
      "JqU20SzY-YB05Xj3bfSYptJRPLO2cGiwrwjRB_EsG8OqexX_5le9_8x-8i6MhY3xGX5LABYs"
      "8dB0aLl3ysOtRgIvCeyeoJ0I7nRYjwDlexxjl9z7OI28cW7Tdvljbk-LAgBmygsMluP2-n7T"
      "58Dl-SD-8BT5eiGFDFu76h_vmyTXB1_zToAqBK2C5oM7OF_7Z7zuLjx7vz40xH6KD7Rkkvcw"
      "m95wfhYEZtHYFwqUhajE1vD5nCcGcCNhquTLzPlW5RN2Asxm-_Dk-p7pIkH9aAP0k",
      &p));
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AMTv-c5IRTRvbx7Vyf06df2Rm2AwdaRlwy1QG3YAdojQ_PhICNH0-mTHqYaeNZ"
      "Rja6KniFKqaYimgdccW2UhGGKZXQhHhyucZ-AE0NtPLFkd7RhegcrH5sbHOcDtWCSGwcne9W"
      "zs54VyhIhGmOS5HYuLUD-sB0NgMzm8vNsnF_qIt458x6L4GE97HnRnLdSJBFaNkEdLJGXN1f"
      "btJIGgdKN1aOc5KafTi-q2DAHEe3SmTzFPWD6NJ-jo0aJE9fXRQ06BUwUJtZXwaC4FCpcZKn"
      "e2PSglc8AlqQOulcFLrsJ8fnG_vc7trS_pw9zCxaaJQduYPyTbM9_szBj206lJb90",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
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
      "AI3R7wghPU0Mbm47MPGeFvga0lSLsTxJWCuag5wPq0zNi07UuR1RmLvYmPlrl1"
      "Qb4JhKoz48oDEbD2e0cRC7q47duIRM1keOo7NMZId6VYp7pZEmBbvdBxDgyXNouE_dh1JzsD"
      "PXysZr-IsWo-YadO9XzNt9a-GWNm1-wFXlqjvuFpmSvEVc-kzKcd0LrJJgdXJLEbp1n2l8uH"
      "fQwLhkr3pDA993Z8sG6byFitH_B5Sya1csN3UcO8BbYRPFK4bxQtIXCY0YN98ZODzjvoOfSN"
      "jasOHnTprxw-v13rxLXzeJZZlOpkaNHGnjovuoe6N5NqcH1XkaLho0sanMnhJL4zU",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AL6gykI07B_tLc5MEUbwAZec8frBkcIvwdlnbchmov9q5sBnI7xJt07BJlyrm8"
      "p_XWuOblmx6Qg4ccKwE1jt3Cd36J7X92D9IJwfagytmeT4wmruM7Qbuzg7iGeX4RJ4CLkvsJ"
      "ZRSh8Fvum-qMwEynypVJMB5-Uw8Y_6Cd_nMZeSK7pJs8ewrS7LDY7ODnrzxkJ1xRCXpVbvsB"
      "0mKcOmhM9fD6Q1qkjwmBn4MYBE2D1im_S2Ybt2AiSjAxMX6M8u8N8hXcEu0ozeTfsZy1HOF9"
      "HuTRdOdEh4P-ZvzQqawSLF5HTk82_-F-yiTPhtlcqCNFbCs0pKGeZIFZQ9ZfK5kn8",
      &q_inverse));
  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p_data.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q_data.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  absl::StatusOr<SecretData> q_inverse_data =
      ParseBigIntToFixedLength(q_inverse, p_data.size());
  ABSL_CHECK_OK(q_inverse_data.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_sig_gen_test.json
RsaSsaPkcs1PrivateKey PrivateKeyFor4096BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "46595b9E3n01fiOMjf8GPKcTRwd3q3hrSViE56m6Hd5l3n0rW-Pyt9GDDPbKjtXAXT8JSqrr"
      "HdLksu3ghhMQmpujTH4r-EUCJZdDdEWfFtosFBksY3mF_r677wHwOB540P1jt2A49ePTXcfS"
      "JDljNmr112hfG8_JncuR6UyTAZBoNTEi7dA8w-YV4Xwb8d18Q9rob0ekAjj7WUBBzr26JfP-"
      "lZOmwym398R26rdiXRe6e-eIaTa3M_jc5ubJN_WI2hMVwRF6vSnIOJXZWYjRf5_XYjlg2OQz"
      "18aEFQf_L6rDbg4ZpB6yzM2yosD66WZxmpnSA8kkNJvA7qE3Tv0-IwmbLRh5IgFv0BQIdSCm"
      "c2NocyK5DXqJDY9EZKjHlNKj8gcMzTsOu8orQrv466bywL-ACLVhbue4Finr_5epOluGGYna"
      "oQ2nyOO8ewzbCV9s4Rhc-P09ygNes-UFy-Ai2B2TlFoUSAa5_gugfzq5xw5ytft3rG5MfgOq"
      "Lc58XvInq6Gs1Iwdk-DibwHo8eQ6qXiA0V1skksGDR-s4h0Dp5bIYwH0p0M55HKy-WzQdVdB"
      "y53zU1B3OBrahNG8CEamxEyKjTz-G3qZE9Hz168sXqTmfOCn7TwAWCBv0TrZzK1aghLz7NeI"
      "NoprYUgXjHxeqNbThSJ_LHagRyFuXiBrHtE",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "-NurWsBHmwDGl1H_zQ3l45jesL8M8Zplngm2rMTFaXhZAbdYieJ6bO6KMJcIptaKUb2T6LJb"
      "hqXCFQtP_5Ygl02qaBTDYB3Oj9zM4avm5nN8lI_Zt8ij2QMqM5vG7oSO5PpU9RPDV1t6iTJf"
      "fJexvrW2Bv6W8rMpP0zqwZTAkBNO-TCgSILx6Wg4woJ9jqUSz0dKS1ZA9G7iWA34tZpq_KTB"
      "4fmjuoIjK52yfp8rSNUYHseB33laqH6ErRXglf5D1Gpu2w1H1ihkh3aSx1TCk1R4Z3_kzppC"
      "kGOdikSOfiw5O8VATxTdN-tmtLI__QcdNG_W5Z0y8K4cECn2VtdPZw",
      &p));
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "6jc9zFaNE0WwOB3hkhccINjIwyxaW6y4Sr1yy5b-xJL-TtNdemXlc52Fn7meKy5DxZDHjsuc"
      "B6QNd5OqeNyzHeI2uXNbby8JzqcOqSEnWoEoIby-OGm4iDvrJAkzT44KlvRSgVfePyMxgkDm"
      "XT3Kmj1D3gg0W8Ls5LrGjHoh0pxaz6IwxRjJhzY8N6zStvbL1p__mdOmGcYmi-AT06i5bCgX"
      "5gaGPT2MEjMG_n9rjcAn2rpopnhL_0FLNSZJvHdp659hwCu4x2J4FEhPJ5kjPIGJjGeSVvEL"
      "yr70aE7ISyWd8XUaSaFTwOhDV-6MyeNenlYWr5sAQE5VRSst8IeVBw",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "w7RlDmpWJZS3mHrY8xZx6snmnxKwCDSGo4E6EqZwJWCKhqn8S_s6kf4J2Op92E6x2lR_RCk3"
      "hy1F8yzBTdtvZ-2hDFb_ys_GCSb4TKTWYfcCSwbRjhGQoPI3NvzTtfGzOmmPdGiFX2bGd6yQ"
      "oTfehX77VobSiKzSzEAeAfyMbwFwQtG1yzCHNCpNMNJUEWDJ6Q5EY_jB_jhRcjQSmiaE6ohb"
      "HO4oj10WcY-DtsZP0OgcHuCAxxD1dbqBdmjVBMA_8YV-BnBsRQPhAxMBnRaQKjLsuWA_vSZd"
      "IJXmZ71AXgNDQzj9OPPMgNR0IbhoUAFPO1SUqGA2lkYmNaP6YRLUEw",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "tD93K76gK2jCSS2V31wxpYWwW6PSliLCYaKSqeO2hYmqdPdtRTkN8IAVyeqLsyeTuIPHUDma"
      "BrdWNeRKmWEf56uj-eyxPUux_HvMaJS_OIOVYwFiUv_pp86VE9KQznS96ZZ1uFzrCSQIgfl4"
      "T-Gx_imQBVvDD6tfrFehXZLQXMk_ifOEHOsKjShMB3zVXUFpde8EQloDxmocWCFGoOmEaZwh"
      "aEE1JgQrvAXRKCLfnuN2yHoU96g0tGiHfIvOy2AK_-5UyBPdzHQXfWR4pjzQRUxbktZSZN50"
      "-L8kUPHwawS0HJLGfEvPrPISgaVwbB6zPp96LgLXmqWuMeEdJbLyGQ",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "jS_QDRbPo_27OplYHMTPPm4x7Wnc3cYqmJUw-FmssG3fCqjWECDW9wCnznGRa0Cclj4C2WqP"
      "9-0V8JFlCRPNDEmQPY0Dbz0hkU7JNNgID4kb5TxFZmqBO29djl8irCAswaDFEx8G5ftH4MJa"
      "VZmgjSheAqTtJhH6tH7-CydgS_hxfsEVNbAt9pILyH5g07Fy19cOvwSCrFnU9tNBJPz0YBZf"
      "4G-uJ2pdycZAfmkcyz_WdUML5r4DbKGILrSKr-CjvgPg9vmjW77Hsb5UUu6yHeqCQnDZBkcq"
      "mh-zhqCs2Z2d9NPPKOw6HbzsDvsnKWsPVA76aVgoZDuVwy0Be_xSdQ",
      &q_inverse));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "hfmTk7GtMM60v3jjqFq8rMwTh-RZAsllOE-iRT-WiSTpBLba4MONe6UJXIOMReh5vWTubsWM"
      "fIwwjylyyPJG_vM-cDB-ZyUUUlJkGvMs3iGbdmgpuo8zzecmZ0nYtO0ZYsD4AFvaqLZbFgAT"
      "I8WxH8Bo0UxVSuRGW1gCkCnDB1SWPVagmxfB6fRmQ7zoJLaT_Mm_pFufor8tCCPLlYAHHXYq"
      "BJJRut29p0owP4WRl_3yeh6QInlT7H0wX57GIOuWj9xTHLzQYKdJbiKfNxRPUq4X63CgEICY"
      "EQx7hHSkMMRnI0egxvZZeDJCP4sXGmhxyOtirV-asmpEaSbsiMpz2MX3wSM1GRMqbaDzt15S"
      "cQfUaZ5-3J4dAowRfNbNWoTAV6m1ezt8FXGvgCMzbO1u5y8ZrDuSshQp09uUCsOHG3gdnCun"
      "AYT3tjhuTU4WNAKF9eIuiS1H4EdaG85Nfo3CyVgM2GhOQUIhZes8sVrWey-57k-2NIKrg4wQ"
      "7PoVcwppL40PHKdAeL_3ABWzoerYvbiXJyQY9vJefAM8FClRSt-v99vmhiP30X9A8yZ0n91P"
      "qwwkv-kMF76HpJiZwV2D1STwTA9VEK2rQ8nd-A4btLaLcAoIZnRogktbXTWGYLDCeO2c-PWG"
      "WEiH4gZXpg98QVD1PoyfiubztUbYQTX7ABE",
      &d));

  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p_data.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q_data.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  absl::StatusOr<SecretData> q_inverse_data =
      ParseBigIntToFixedLength(q_inverse, p_data.size());
  ABSL_CHECK_OK(q_inverse_data.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(parameters, BigInteger(public_modulus),
                                   id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

const SignatureTestVector& CreateTestVector0() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "3d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bc"
        "a418828dc140e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc"
        "2a488faf35199b2e12c9fe2de7be3eea63bdc960e6694e4474c29e5610f5f7fa"
        "30ac23b015041353658c74998c3f620728b5859bad9c63d07be0b2d3bbbea8b9"
        "121f47385e4cad92b31c0ef656eee782339d14fd6350bb3756663c03cb261f7e"
        "ce6e03355c7a4ecfe812c965f68890b2571916de0e2cd40814f9db9571065b53"
        "40ef7aa66d55a78cd62f4a1bd496623184a3d29dd886c1d1331754915bcbb243"
        "e5677ea7bb21a18d1ee22b6ba92c15a23ed6aede20abc29b290cc04fa0846027";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

const SignatureTestVector& CreateTestVector1() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6"
        "358c78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa41b546c6751"
        "fd49b4ad986c9f38c3af9993a8466b91839415e6e334f6306984957784854bde"
        "60c3926cc1037f764d6182ea44d7398fbaeefcb8b3c84ba827700320d00ee288"
        "16ecb7ed90debf46183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05"
        "012f99d5df4c2b4a1a6cafab54f30ed9122531f4322ff11f8921c8b716827d5d"
        "d278c0dea49ebb67b188b8259ed820f1e750e45fd7767b9acdf30b4727573903"
        "6a15aa11dfe030595e49d6c71ea8cb6a016e4167f3a4168eb4326d12ffed608c";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

const SignatureTestVector& CreateTestVector2() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "019988776667cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba4"
        "1f955d64b6358c78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa4"
        "1b546c6751fd49b4ad986c9f38c3af9993a8466b91839415e6e334f630698495"
        "7784854bde60c3926cc1037f764d6182ea44d7398fbaeefcb8b3c84ba8277003"
        "20d00ee28816ecb7ed90debf46183abcc55950ff9f9b935df5ffaebb0f0b12a9"
        "244ac4fc05012f99d5df4c2b4a1a6cafab54f30ed9122531f4322ff11f8921c8"
        "b716827d5dd278c0dea49ebb67b188b8259ed820f1e750e45fd7767b9acdf30b"
        "47275739036a15aa11dfe030595e49d6c71ea8cb6a016e4167f3a4168eb4326d"
        "12ffed608c";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

const SignatureTestVector& CreateTestVector3() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kCrunchy)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "009988776667cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba4"
        "1f955d64b6358c78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa4"
        "1b546c6751fd49b4ad986c9f38c3af9993a8466b91839415e6e334f630698495"
        "7784854bde60c3926cc1037f764d6182ea44d7398fbaeefcb8b3c84ba8277003"
        "20d00ee28816ecb7ed90debf46183abcc55950ff9f9b935df5ffaebb0f0b12a9"
        "244ac4fc05012f99d5df4c2b4a1a6cafab54f30ed9122531f4322ff11f8921c8"
        "b716827d5dd278c0dea49ebb67b188b8259ed820f1e750e45fd7767b9acdf30b"
        "47275739036a15aa11dfe030595e49d6c71ea8cb6a016e4167f3a4168eb4326d"
        "12ffed608c";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

const SignatureTestVector& CreateTestVector4() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kLegacy)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "00998877668aece22c45c0db3db64e00416ed906b45e9c8ffedc1715cb3ea6cd"
        "9855a16f1c25375dbdd9028c79ad5ee192f1fa60d54efbe3d753e1c604ee7104"
        "398e2bae28d1690d8984155b0de78ab52d90d3b90509a1b798e79aff83b12413"
        "fa09bed089e29e7107ca00b33be0797d5d2ab3033e04a689b63c52f3595245ce"
        "6639af9c0f0d3c3dbe00f076f6dd0fd72d26579f1cffdb3218039de1b3de52b5"
        "626d2c3f840386904009be88b896132580716563edffa6ba15b29cf2fa150323"
        "6a5bec3f4beb5f4cc962677b4c1760d0c99dadf7704586d67fe95ccb312fd82e"
        "5c965041caf12afce18641e54a812aa36faf14e2250a06b78ac111b1a2c8913f"
        "13e2a3d341";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

}  // namespace

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_test.json.
const SignatureTestVector& Create3072BitsTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "dae3ab3fee3cfb9e1855bdb9eda8bca1219de7fb41c1831df5d80c58f5a165ac"
        "c917dd0b0ce96a434577e049f1c72f1027567cf0e15d87efba14b2973d1b82c3"
        "721be713dcac6dd6385abda8c73f14a48a7b2cee6531692d0dc0d9f99e5abd55"
        "08d2d6a1fdc62f3ce44f08a41294d53be8ee253ee01463042bfb067feeda7b07"
        "54cce598d4fcf83e7e0a9478d0e2d2e5b9c684e54bd99da29e54d81b2cd37f94"
        "cab6be7e67bf0c2aa3263de7ade4f05791c5c2c52115a918a4fcdfe936722bd8"
        "5065ad9fc20fe273f4f2d7504c210d70157eb565d199b521b0315909a8d885ab"
        "4b82877ed505fc02aefacc62c8b5c3e6b56dd0a6b2f1ff1dda7fd0ca7627b6bf"
        "815b9588f477040084f8581c8ff31684ff992fe6652d6a4f2bcf7aeb6d26766c"
        "2f52863ae9e3de7927320a1cb6ecc85b59307c50c60bf95f08bd99908f0cac63"
        "b52f294cb7e2fcbdffcc4e75c32a64adbb9267ca361029433c7537ea8ce25e92"
        "03a40e3cf2503c40e921643bb7e26a4b14eac85cd5451c2f80b35fc8c5b060a7";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor3072BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_sig_gen_test.json
const SignatureTestVector& CreateWycheproof3072BitsTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "9858e2557c6b99fbd84bc7eac3e31283a4efb351ff019343760a1e282368938e"
        "29ad902d3eb6cb29b35a036dfbcc7e06d2f1d15548df59ced35326295375bacd"
        "7a9d28a01b4e8acfb676d80b6295e19c6b7a259df56456e1df72f6a746e9cd31"
        "fed9b79b35d7a30a7aa257e9e8ac60ea886042b9194e7a383d1c9f71c84511fa"
        "f6c96f7ae0e690112b26bb60cf7bb10f684e4fbe2a3a1b1c0caa9b1bdc79fde2"
        "3fb758c2ba57880a4de461ecd2bc696689438183e2b9724fa68258f461bb4405"
        "425620a4d95c87ddd83e04be381bc743b05d26ede2ceff8a858636baadf56ef1"
        "dab54080da0f516307c579833717def053c8906d4f102448ab22693e7f52d585"
        "0193a40ccf0d68d1303953771a73924e4bcddd8486e1477d96250bf6b480a5f4"
        "b822822183694c52a2edacb331564444f0335d3b17d511ece59889b6d961767a"
        "3192d7f081caf7e671addb3757451776d4bd3b03f7b689843dcd59019ae4f292"
        "dba54738a88b86cc6ce3b123c61a446f4878b627a7f3585d8ab7bca9b258f10b";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor3072BitParameters2(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("61"));
  }());
  return *test_vector;
}

// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_test.json.
const SignatureTestVector& Create4096BitsTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "0d3a81c5fb4389ca746a2ad65bfc158e97f89946a88ce7ca966bd94c8e24becf"
        "8faa3c8f5d13c29104dbcaf2f6a395d3d3b88ab32c3d53fcdb1757082c9fe91d"
        "5410f11d15b4f5bf471348b4bc7fa501db58fe81a4ad067dddc9177ec0247bbe"
        "d5fb66b9f6d3adb531a3804bd5eb649a707cded75aef163480c35b84e91df2df"
        "43d8d0702b284557b1c16eaa7a045420bf1d595aa90d30f1606f8a97a8f64d54"
        "1760830ddb75cb9edb34f39397be62faacd2e9d4b201e9ef3fd4025186fcf152"
        "88e83817a7d2d6585343bb3d1add7b71b67687bbe95012d0aacda9dde6d03430"
        "5c2ca90adcd4dc8fea1d146b16c600bb749f70f7206163e74e95ddd63923050c"
        "eb66dda281d53fe5ffd776bcb9c0ca527fc034d743d5560fa3bab5dea1f22276"
        "314704a2582271e034ecc68eae635e772dae161b82b54fee6a278e1ab6262b52"
        "5551e63d562d3ba0ab3bdbeace66f590dec4e680ef48222afbda1e31d5b5c26e"
        "67d282fcf6fce1a45aab29243f7b87e3d1a1ea0b3eee0a237abb933635c68de0"
        "e6038d83423df61b76c43e980140379c5b4d134226e725fbbf939a41ba21716f"
        "a7e4bf7af9bd955fc07a39bc8d40f50659165a2cf58639028242144a209214c0"
        "af3e3658b8be9b291ca369a14631532ae962b44980d3acd86bb6483a95c1f2a9"
        "1dfec289ceaa207a7a496213ebc13e50a2f84450b68255d718793b7766bf4686";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor4096BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_sig_gen_test.json
const SignatureTestVector& Create4096BitsTestVector2() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "798f597e9ad4ba8b3d00a9527f4e785af5c55994e2953046a1b9062945e8dfa3"
        "5eedb1e31af3daf1955d7b0afe74fbc53739b1aa02fa2dba629c31b211cd513e"
        "2248ed847dd579406ab603d3369de3bb07143a581734fd8b1ca0358c4fda6390"
        "45be1f192b233efb8848bb2c544e4e188e0c7ce311bb4841077d15051c6f6b31"
        "998ddd8a7bd30d75b7b3c824358bccb35f8ffa8c0fc5ac37ed71cdd48ed3c026"
        "9a638317756bdc9287043be1b4f3c6ef6423f1d0d38857c195e7be81c3778648"
        "ab889474109ff3c7be0fec790d3f5f50b966e3df40c566f572f8f252d09e97d4"
        "c90442badf820c7db74d6fbb004bd7eb53c0b1a871bb9f480821bbb48b363c85"
        "c9866bf8a86de9c6732a3136f2c80e88a29540a9036b72fb8f4c898e7b487c41"
        "d0f693c91309bb3bc06f1e3b2fa9918c31ba2a4b82a37a927784a7c7d2aadc33"
        "01524ce2708774c3e2189ca188b3d85a33348d28ed6f080a06452bf8316d483e"
        "6a5e28b831797f85a8ca5ca922bcd94b9045f588ea9e15f2a20dd26817eeb80b"
        "3421c5de72db98843dc719cfb1aff1f927ee1df1bb718732159bec70d5b6d0f9"
        "8a3fd5d42c31ecf4124cb1759f183838d676eca2cadb4d57f2d6a52cd0115ffe"
        "c0fd79c99aa78df8c6b54797a590bfefd4c34e4c3f39750ba47f4d8002a131b8"
        "70ff8e65c6c37b75e5c54c8a2bc2fdacedb41f30ed8bc9029819b7064b6514a1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor4096BitParameters2(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("61"));
  }());
  return *test_vector;
}

namespace {

const SignatureTestVector& CreateTestVector5() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "71ae1ecd20509a12627a876e2efcd67015659923b9e2564405673641d73615eb"
        "937625db427b55c582b97172eeddabc247ee2f0f44652c8310d433f4cdbad3b5"
        "58d2640414afc70725fe40849d2652d91413a9ce5ee2f234cae1fb1a35b8b345"
        "2b60ca33d38c6c84b2feaffff1c0f5be3deab76b3cdff154f76c18bfdbe18e0b"
        "62ea832986802e9a07eeeae3b367c551c6672cc64e1e9e13bed3352d6f8a109e"
        "baf86a90a973939f4c6a7b4f0ff214228051bdfd1c00ed2dda804e168fa42478"
        "35b25a8d88a57b8e042c45cedc00db2cd03f5bd4ec5647e90737e5325ce2fc3e"
        "cea2af569d1fb51a8332f4b526ba214b0b8d10d562ba2dccb0267c85098d8ff1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

}  // namespace

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_2048_sig_gen_test.json
const SignatureTestVector& Create2048BitsTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
        RsaSsaPkcs1Parameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
            .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "38c042a00d6f27742a46f1f963a7b2e04f0eac637849631a491b8e4e58fc721c"
        "6ce620d5e705dc8e73409c3909c1c68b6bdb2b30f882cf2797e65030b38c4e7d"
        "af6fef9d1f115c890086cf54ca3e7c2b21dcbfd1250ed1d925810970f17dbf48"
        "2d1784f296adee9ace6979075c1e12f5580cfb322e8737db9d127d38e1b99ed8"
        "7ec49448a18a6fee650d3c27e4a2a86a3d6e3ce4fe64120be60872fa07a3f78a"
        "112715c167fb6c900698ba1afd824087a4cf733335c4a6d5120e3b29bc42f3b3"
        "d5db79973e4e321e0910a288d18cdba172d060283c4f4c6656e9175a18b756b7"
        "d06251e9060bbfcab04978853eec6032850a0e757bc0c61ad38aa4eb6bb6d907";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters2(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("61"));
  }());
  return *test_vector;
}

namespace {

using RsaSsaPkcs1TestVectorMap =
    absl::flat_hash_map<std::tuple<int, RsaSsaPkcs1Parameters::HashType,
                                   RsaSsaPkcs1Parameters::Variant>,
                        const SignatureTestVector*>;

RsaSsaPkcs1TestVectorMap CreateRsaSsaPkcs1TestVectorsMap() {
  // This map is used to look up a single test vector for a configuration; as
  // such, having one item per configuration suffices. By convention, the first
  // defined test vector per configuration is used.
  return RsaSsaPkcs1TestVectorMap{
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha256,
        RsaSsaPkcs1Parameters::Variant::kNoPrefix},
       &CreateTestVector0()},
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha512,
        RsaSsaPkcs1Parameters::Variant::kNoPrefix},
       &CreateTestVector1()},
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha512,
        RsaSsaPkcs1Parameters::Variant::kTink},
       &CreateTestVector2()},
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha512,
        RsaSsaPkcs1Parameters::Variant::kCrunchy},
       &CreateTestVector3()},
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha256,
        RsaSsaPkcs1Parameters::Variant::kLegacy},
       &CreateTestVector4()},
      {{3072, RsaSsaPkcs1Parameters::HashType::kSha256,
        RsaSsaPkcs1Parameters::Variant::kNoPrefix},
       &Create3072BitsTestVector()},
      {{2048, RsaSsaPkcs1Parameters::HashType::kSha384,
        RsaSsaPkcs1Parameters::Variant::kNoPrefix},
       &CreateTestVector5()},
      {{4096, RsaSsaPkcs1Parameters::HashType::kSha384,
        RsaSsaPkcs1Parameters::Variant::kNoPrefix},
       &Create4096BitsTestVector()}};
}

}  // namespace

std::vector<SignatureTestVector> CreateRsaSsaPkcs1TestVectors() {
  return {
      CreateTestVector0(),
      CreateTestVector1(),
      CreateTestVector2(),
      CreateTestVector3(),
      CreateTestVector4(),
      Create3072BitsTestVector(),
      CreateWycheproof3072BitsTestVector(),
      CreateTestVector5(),
      Create2048BitsTestVector(),
      Create4096BitsTestVector(),
      Create4096BitsTestVector2(),
  };
}

const SignatureTestVector& GetRsaSsaPkcs1TestVector(
    int modulus_size_in_bits, RsaSsaPkcs1Parameters::HashType sig_hash_type,
    RsaSsaPkcs1Parameters::Variant variant) {
  const RsaSsaPkcs1TestVectorMap& map = CreateRsaSsaPkcs1TestVectorsMap();
  auto it = map.find(std::tuple(modulus_size_in_bits, sig_hash_type, variant));
  ABSL_CHECK(it != map.end())
      << "No RSA-SSA-PKCS1 test vector found for modulus size, signature hash "
         "type, and variant.";
  return *it->second;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
