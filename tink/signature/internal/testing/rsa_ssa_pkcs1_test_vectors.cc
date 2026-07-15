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

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "absl/base/no_destructor.h"
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

RsaSsaPkcs1PrivateKey PrivateKeyFor2048BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "s1EKK81M5kTFtZSuUFnhKy8FS2WNXaWVmi_fGHG4CLw98-"
      "Yo0nkuUarVwSS0O9pFPcpc3kvPKOe9Tv-6DLS3Qru21aATy2PRqjqJ4CYn71OYtSwM_"
      "ZfSCKvrjXybzgu-sBmobdtYm-sppbdL-GEHXGd8gdQw8DDCZSR6-dPJFAzLZTCdB-Ctwe_"
      "RXPF-ewVdfaOGjkZIzDoYDw7n-OHnsYCYozkbTOcWHpjVevipR-IBpGPi1rvKgFnlcG6d_"
      "tj0hWRl_6cS7RqhjoiNEtxqoJzpXs_"
      "Kg8xbCxXbCchkf11STA8udiCjQWuWI8rcDwl69XMmHJjIQAqhKvOOQ8rYTQ",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "7BJc834xCi_0YmO5suBinWOQAF7IiRPU-3G9TdhWEkSYquupg9e6K9lC5k0iP-t6I69NYF7-"
      "6mvXDTmv6Z01o6oV50oXaHeAk74O3UqNCbLe9tybZ_-FdkYlwuGSNttMQBzjCiVy0-y0-"
      "Wm3rRnFIsAtd0RlZ24aN3bFTWJINIs",
      &p));
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "wnQqvNmJe9SwtnH5c_yCqPhKv1cF_4jdQZSGI6_p3KYNxlQzkHZ_"
      "6uvrU5V27ov6YbX8vKlKfO91oJFQxUD6lpTdgAStI3GMiJBJIZNpyZ9EWNSvwUj28H34cySp"
      "bZ"
      "z3s4XdhiJBShgy-fKURvBQwtWmQHZJ3EGrcOI7PcwiyYc",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "GlAtDupse2niHVg5EB9wVFbtDvhS-0f-"
      "IQcfVMXzPIzrBmxi1yfjLSbFgTcyn4nTGVMlt5UmTBldhUcvdQfb0JYdKVH5NaJrNPCsJNFU"
      "kO"
      "ESiptxOJFbx9v6j-OWNXExxUOunJhQc2jZzrCMHGGYo-"
      "2nrqGFoOl2zULCLQDwA9nxnZbqTJr8v-"
      "FEHMyALPsGifWdgExqTk9ATBUXR0XtbLi8iO8LM7oNKoDjXkO8kPNQBS5yAW51sA01ejgcnA"
      "1G"
      "cGnKZgiHyYd2Y0n8xDRgtKpRa84Hnt2HuhZDB7dSwnftlSitO6C_"
      "GHc0ntO3lmpsJAEQQJv00PreDGj9rdhH_Q",
      &d));
  absl::StatusOr<SecretData> d_data =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_data.status());
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "lql5jSUCY0ALtidzQogWJ-B87N-RGHsBuJ_0cxQYinwg-ySAAVbSyF1WZujfbO_5-"
      "YBN362A_"
      "1dn3lbswCnHK_bHF9-fZNqvwprPnceQj5oK1n4g6JSZNsy6GNAhosT-"
      "uwQ0misgR8SQE4W25dDGkdEYsz-BgCsyrCcu8J5C-tU",
      &prime_exponent_p));
  absl::StatusOr<SecretData> prime_exponent_p_data =
      ParseBigIntToFixedLength(prime_exponent_p, p_data.size());
  ABSL_CHECK_OK(prime_exponent_p_data.status());
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "BVT0GwuH9opFcis74M9KseFlA0wakQAquPKenvni2rb-57JFW6-0IDfp0vflM_"
      "NIoUdBL9cggL58JjP12ALJHDnmvOzj5nXlmZUDPFVzcCDa2eizDQS4KK37kwStVKEaNaT1Bw"
      "mH"
      "asWxGCNrp2pNfJopHdlgexad4dGCOFaRmZ8",
      &prime_exponent_q));
  absl::StatusOr<SecretData> prime_exponent_q_data =
      ParseBigIntToFixedLength(prime_exponent_q, q_data.size());
  ABSL_CHECK_OK(prime_exponent_q_data.status());
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "HGQBidm_6MYjgzIQp2xCDG9E5ddg4lmRbOwq4rFWRWlg_ZXidHZgw4lWIlDwVQSc-"
      "rflwwOVSThKeiquscgk069wlIKoz5tYcCKgCx8HIttQ8zyybcIN0iRdUmXfYe4pg8k4whZ9z"
      "uE"
      "h_EtEecI35yjPYzq2CowOzQT85-O6pVk",
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

RsaSsaPkcs1PrivateKey PrivateKeyFor3072BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "2R8NAPGqtYDirA6DdjjecAT8loviExWh7yojSWkEXdS8GUXrU5gu6z_pfOhKJsfUZHhP9-Vh"
      "zuVw4m1BReFP_M5wQw7zL6zRnoDMzoqbZgQGX_HlCn-o_dQyyk57K4WMiKlmJuOhCoMVlvkc"
      "LyLIPhoCZ_x98SHTM387D6aoxgbtkDHB-DuSE96oMtxdyunAO0eAmVPXXZZvNbyxD__SM0Wm"
      "7icUw4iXKYCTitYSPZyXkWkguUEu4ahOHTRbg4ZuKzsCEnOEaBrKA4QBo5urXkZy1kk81KKT"
      "uTMlLj_AbY5DSPDha5muWPeXK0O7anoEKV0RLuUJ-vquOd5tBk9iLD88i0_ObYNnMMEoXZDF"
      "SNtit5WWR5Tq8UOtQnNgoug_Wx-KILCNGM29R08hwb9C5vHhN4kN-SiI2DzEBZdVlyCbegn0"
      "3Jmfq4LU69d-DWa9idg_pWSgPjVgl3-04PunoDOfkiHcDJlAJYHLlUcqbBG26A6RBZ-8FEcL"
      "emjY5Q5T",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "8mG_wJd4bhw00SPBnNDQtsxlvvUnIMigA4krDnRhGIgJmrlsAyoHi3fgAL6Q1bmPuOQIPNky"
      "atrQUOxsuS9Vtb-AZrEGXj-_0TPuzay3XM66ZnPSGEupoKlYM_t-DCfGB3d5R-rP5wLdzu3x"
      "amX-l4q1NVIHgI-ipZDxczuZ2RZJYu1c-YtHjNAoj_FhlDrRo_3RNTXHUvYiz44MXDukOru6"
      "-QHcRX-vEeCSIkc671PRdgYfo6cHQbq41UCpWeHH",
      &p));
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "5VH4x-83GMB6qfUSej_oQ55w-6dDUkJnNV-Ala9k_XwLR1bMQ1VbthV6SIBG8cyZiOcWlBZB"
      "FrJQKD3VC3iUpFaRjWz46Dv-CFq-Zbvv55HP4XhlSJGrgtZvcMhadXVzoFEDlgU2PDirnasx"
      "EQqTxz-gm29xBoYz7Y_Qd-6AXALVWQkONGoo1xhqa19oBLZfZVs0oqbEa4FQGytHFUzu_mts"
      "IP5zzfdk_HaPck-vKUiycOa1JRhxBGR21DkLXi8V",
      &q));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "AquVF1vhg5XwM7mB-GQ-qBYHnTpfL2jmsvBLus1l1lmVbqIjgMWwXghNMNISh2ORwyKPqTbS"
      "-x5rQv2g_eEFgNBxJQH8D6wKb-6ZljiyLJEEGw34iSaEx4pijYZlkWV1EwEyVmwaQOzXySGL"
      "LTE6UTk0ql66lcqatFluOoUMMlNHfKx__DOPWls0qlt3c9VoHdKFTF1xmp8NAxYs_0tgJG1I"
      "3kjwwm7dnQ8NwXlchBF287zdQCoDD5doToekUHvIvUY-q0mUXKjM3ryitMXIsV20D8sSU0zv"
      "12wTDpXFgGoco_tDWUd3gPQ3h3gT7J8fJBXxayJoFVo5khMlLQuIN7d15KIiMBKyDHZ8eUpB"
      "BEEWhFkK579-QieUnVnZTL-FdG0vppCDmGWR6bCvUQgKt8H0vvDZb6u3MY5koDqTrmL1L8lB"
      "ujoesry87t5ZPc1sSvBFn7d6uQ926tcNv7ckmxfWK3QOKqQ28pn9uUBxqhUY6XymugDwFIr8"
      "8xbd1QfR",
      &d));
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "dcWRSp9O4RHLiCN7nBrKj0fZ2GN-U6uoNI-d4DQkSaswH4IhPZhaeiYRLctqzK6RayFB728J"
      "1Gnl9qwqWADsAJfAaCV0Fq-bIKe_TSizH-FDKSz11OBO18XxGbEFmhppWo9u2sb5piH6bOWo"
      "_C36-t9nFTV6d7lTKme3Kmq3Yog1uF_lYUuPxJgQXYDIDSJXYvudf-FVrLX0TC2VS-ue7Pry"
      "6rNAuHRGOMWJvCYoOMndaR-ol_g8ym9UCCqXHxlZ",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "EZ1MSL89Mi-GvItQkgdapecDsrDUYPssxlLBo73HOhlPHHm0Uu-5jbD0paEE0gnvOS7W8yUK"
      "dt3Xfl_Rf4IRmNX1dDGMpPoGt0mRGmtnMBhpKV6AGSTnUbN69-TL3f3ZldTjO6DG27VWqVO-"
      "_xoa49ElWwsiWWfxkSvczXmKbobhMGebqbcF0A_WDM1VRhdkGHr6_gtlRwS1zIB0g1RXfz9t"
      "HNOuvYFlRmcs-ZDZWYh1_GocO-82rymwXvjKwL9J",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "mZ_WBLgVj7lBYYkXJAVGwypzTKi0h32c75dDiHzTSh2Imgvv-K4bwwQGHrOdVpr1_gsmRrbR"
      "rX2sejeexpWo6cy0TOTxwReM8qvXQa_Pusny-LdJOCBnc0e98IwWtIH7FNKjV4I7tvrys3Mo"
      "MP8nvn6-yOajJczx6MJKUpu1dJgh_e2oslUo_aDkc_vFFht2S4SBNZicK9SZFLttJEhMgYIb"
      "wwqhxKcCsi8UTLL3w1nBpo11WcAPgFoXzuI9KD0Z",
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

RsaSsaPkcs1PrivateKey PrivateKeyFor4096BitParameters2(
    const RsaSsaPkcs1Parameters& parameters,
    std::optional<int> id_requirement) {
  std::string public_modulus;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "owtidA4lqrAZNOptm5IJDP8sDOmDGUHrmDdqLaq9pq_OJUYX9txXn5fCmfqJyl90b-NpMHWh"
      "NXdLcDsAi46ITqbqJaXMa5L5syjXcTlAEJD65p6-Mns2Y2MG_4tKE-bnXUPrbPhWqIhEKp4D"
      "orvCLQA_6Xxz_eSjptscVuHVyPteXJN9YOJ1KVSguxlKK4T1ChK-GDSTuANf9Ws48bQO04hc"
      "uGR0k0L7fVd-1YZLtC_Rsx4tQOI8cZIzXJo_xrKHDJ8_swN88hxs6ifzlpb1Yc4LYLXw35S_"
      "ll6DZNjB_B6ml1XuZVQOBRxUAqw9k6HGWFPLtCMbZhmvsHtY58eJjS8O_rEZiZq3vn9REOf_"
      "z5eiJrxt-bWsfiFkU2nfr1ldBWlGleXasBTtGwaGrgZXQ6T5fxWpJyOZDGnIit8EJ-P1w1tW"
      "EtEDgVHl5ONZ3oUOkQuEGy1Ywv67XHc-cH0XEnjy6bINH0_AUnT2BDAk6mRLjtfN311_ekA2"
      "YwzjIg7KkT_MTT9j2ANqSadsC5w9PYFfYdmMN8Enkf4wD8OamwX_KKXF9UBw8Cm11CFOh0kS"
      "w5K9kunIcKZweSeg34Zthy3Px7DBM2Ie8fHAHcSFkgpmkgqBXMNfTO7aQOXe3vMqplQ27zYO"
      "TBDsHJcMWZD2N37haATJ8A9qenUcb7zpc9E",
      &public_modulus));
  std::string p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "2yC_8PVT3Bdt6Guq5Lk6yVZzxvcVuz8RuEi-yB3koN-EYSG2OFqiVssqnmaZZZahtbUyJXy_"
      "B4gZuL87v3gBRBgBq_5JDKhOXXSC7mIR8E2DBL4SJoTR3IzfctFL-FvXYOwND1Aw5e9ioM6y"
      "daLVfZXz1j455NKpfbDiQ3k78y6DAwzAoL6jiCTm0RiLQXA8wppPYAKNiV7PZKnMs7Iox-Zs"
      "sdsxau2SQzxjsERfHMA0YOM0QO0qI_kB7siSXnZx4wL30ial50HoKYLmfFhBniIQUxnO_86b"
      "wm7Yn4tZBCspdPYJf0I6IuJlZwK42IE6X95VfWrbbn-k5Yz48Hdpcw",
      &p));
  RestrictedData p_data =
      RestrictedData(WithoutLeadingZeros(p), InsecureSecretKeyAccess::Get());
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "vnrCYzg2WTyJGXXd7RN9QPnhhRn5IzMEjxGBsLnsEgdQL1xfDRzVg2W_8-gLNQsBmQseqF4m"
      "P4rfS2qZ6sEyVUhV0lXCJTu69yLkG4k8gcyZM1YAaLIm4UfUWbmnPvGvKrlqKzmp5AE4WnE6"
      "hgq9O2rZFX3WwlCPGFnLhHF9TVM6etCuknNOCFlWxAqfphJVXmgkfmclI4aOBs3CPmJSRTdD"
      "WhQpJMfEZrLMie8oHCMK5v4SOukkieODQH5tueWoWfj31uOmi--RRJRCAib-QSMEnDJOsNzM"
      "4LfuE4L7uQsD2Hqq1ZbSMr41LYPgoBusZk_6lI_85BmAa2gCnFDsqw",
      &q));
  RestrictedData q_data =
      RestrictedData(WithoutLeadingZeros(q), InsecureSecretKeyAccess::Get());
  std::string prime_exponent_p;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "q9tAjjNqBLhfW6RtkBrxzww9mzMX2RX6yMRM1FgVglIq2Z798a6rmVSX5UlkTzdXNlKYtKvk"
      "inykZ6-bpWvx2jzVutWg5wttAoCpW1qQ5R11fxeu1oTerpHRgZRCd9NX1Mzs5TCoWP1pJeNW"
      "NUpzE56ycTm2YA8UHN7IZdDEQtIcsBylSqyZRuJiIGWWeckT7i_lxs_Zv34bO8CsKda1gynl"
      "34ugc1NFnfPT31-QFNVtfvtSdQVMQpA9gs_Nc8aDRV6DjE8BWKDo-v2N1MHHHMVsdjBMl3Wr"
      "1U7oGCDKvKk5R2DbS_Jd9BQJIUQSQsL_TEbsV4Oh-0Six-HLL5UHnw",
      &prime_exponent_p));
  std::string prime_exponent_q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "rXTcz73AwEKAFs9e6SV2SlVDKRId7g_nduFaWLT2ZPSD8J0NccNwK9fclSAaFJORQOz_XhNe"
      "gT7VWLgascx9KWxVutSdl4ptF-COGQVANHM8j6MhfDW_cicXGR4XTxqHiUCPjg1UyGzUBIhX"
      "4vikmhcS2J9fklQJ-wLKcjFnCaNg_bZLQtH9nVy9xohmGbVYSEBN-02yZEeDzm5RFL40bROG"
      "IeF6FiRUlbD80h8XR4ghxXhY4Yyt2WN1gqWfBko8pLIz_1wPrh7bCrh3473eizJ4YETvo99u"
      "MrVL-DivQjLlrZ0HNLnDcLIFew084JBSzljGt8LnaFBQwX5V4kNPQQ",
      &prime_exponent_q));
  std::string q_inverse;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "lHnCy4vPcdXtvcT2UkDOWG6QarY2MgQgzxkGFw068B92f8q3aIgGKOwnlTWJRUoClECfeBJ2"
      "ZvRewH04E5tERcdjj7OdwYqRr12cKOy0f5zrsc4Z5I3L4mEFbuzBB_bTynFfN0evJOauamWM"
      "Q0pozsathGZMiBZ8wlVnsMrCMCqxCcZr0zm-UVjGdHKgGoHpzxne4nYrvpsOr9y7lpkQcNlW"
      "2zAHyytNKwrO-WojP_jd7blwwRwJh_GzvB7IsdlafhBkTJT-b7Zw02OGlJbQ4lzNlWTyg_VZ"
      "gvnHUQjEcMgb87jyjH6FM2g9SUW1OMTWgwg2EKdXn56N0eDIsVxbjg",
      &q_inverse));
  std::string d;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "UNv2icPyXkJTXfDdRwgXwQBT4lt0jvQoWScyW0-QGriZrdajT-Ra-GUVN7QO3fSVFGBd7JCJ"
      "0LBHE3PPg2a-pvMUsHMXfEo51-ZrYlWYNh8Qr4sOnI6KnKOh9t4ncNNU7uYePb6zi4V4-QHA"
      "n9YqKJM1HyB_jez0VG3aEiSSF8jCNXtX9NKadFLqG6AhLpATzlkZOXvpvpq93kK8zPIVYEcC"
      "ZNg9EENp4fGgj1i49rW4c_KFUuZgP5rYKha9hldHrrTTrH4QWypJwZ7qqUZYj5bWAbJ5sQhe"
      "M77PvxXYrqasy-TsBAi5o0M3TtQI_cx_R5LXNZErp2kZvpaNsvU8e6M00PpseA7aezb0NzN7"
      "RzTo3Muy6SywZIy37kjnND6t4u_AEDp6uoo2hnk8yT9Hpirc1Nz7p6IsRDZjjU6PULQkgofq"
      "18jMnH9djABnWsBrx_yMVVnHPD0Pp5pwxbH0kJaxkBFBYpxSNZYA_mUgwrPKsX3YHwJForM4"
      "Vf_Min2zlIFba3f0z2szMZFn3zkCUrfJnqSrrAAuDVCufARtVjHh8COrULBReYDrDKIyu8dL"
      "KXrO4oCsUriq95W1TJ-TuMl-5mZ9CO55iwkQpAOEYv_M7fSuZYdq-8-nRPUqg0Da66K2cMD7"
      "3Y2PlvyVRH1O3j-bYkci-YzE7Eqv3ml4Ivk",
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
            PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
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
            PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
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
            PrivateKeyFor3072BitParameters(*parameters, absl::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_test.json
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
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor3072BitParameters2(*parameters, absl::nullopt)),
        HexDecodeOrDie("aa"), HexDecodeOrDie("aa"));
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
            PrivateKeyFor4096BitParameters(*parameters, absl::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from third_party/wycheproof/testvectors/rsa_pkcs1_4096_test.json
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
        "4e59909b7e8a0c5db68266b9afa27df8cacf9f2da785cf80430080157f6c419e"
        "d7a5e361a7c30995ee4fc65e2d8f6c1a8eba973af303f145ae2a59c1af6a8ab3"
        "275481fcf8f2849e29c5793af6626c7a8e315ad0f98f649d72fddfff3c263680"
        "efd5799a91dde449ac3edbf85e44d3f283caf571935f3b869c199e00b11ad702"
        "417ddbd57322a2d76a669a7ec52433512feee5ead55b5be1b9ed6c4cf8cd476e"
        "bf040972febf70716bb0d9424cf3b27e128189e55bb88f6d54168ab791d03a71"
        "f664018035a27119f05330cde46defd051ba7620912e45fb906572cc45801dde"
        "364323f19991110ae0edc9a0057cdd301755d3aac16f0aec5bf2cb90a71ae9fa"
        "333dc22f918745e94c93ad9eb68658b7909c0ef79076cef26d1c7570bb69ecc3"
        "de41ffc9c9c8445d7d24fab0cbc017f8539fa295f6510e6ebea87c8c1bd2322b"
        "0853a422d22c215e95efc5aae94475809c6ac9fa459be04cdbfec9343f16c560"
        "1cb7e337723066156303e74f649ec6fc3f4b696ed9b158477b9c70751bf6877f"
        "033b84107941dee9d8d283aa3ed1bac98efb49a18846956ffc30ae0485dd5427"
        "ea84944a67516e9065fecca50a92f49b867049f2b06687969e5603a8eda7b947"
        "9fc11fc8a122c20574ff9594c42a852afac6537f0ee586dc59ababbed77fc370"
        "b53579e505298971246f8253a21062e0a97ab45a1612d2502d1db714b1511fbb";
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor4096BitParameters2(*parameters, absl::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
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
            PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

}  // namespace

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
    return SignatureTestVector(
        std::make_unique<RsaSsaPkcs1PrivateKey>(
            PrivateKeyFor2048BitParameters2(*parameters, absl::nullopt)),
        HexDecodeOrDie("aa"), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

std::vector<SignatureTestVector> CreateRsaSsaPkcs1TestVectors() {
  std::vector<SignatureTestVector> test_vectors = {
      CreateTestVector0(), CreateTestVector1(), CreateTestVector2(),
      CreateTestVector3(), CreateTestVector4(), CreateTestVector5()};
  if (!internal::IsFipsModeEnabled()) {
    test_vectors.push_back(Create4096BitsTestVector());
  }
  return test_vectors;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
