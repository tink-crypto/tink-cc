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
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {
const BigInteger& kF4 = *new BigInteger(std::string("\x1\0\x1", 3));

using ::crypto::tink::test::HexDecodeOrDie;

RsaSsaPssPrivateKey PrivateKeyFor2048BitParameters(
    const RsaSsaPssParameters& parameters, std::optional<int> id_requirement) {
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

RsaSsaPssPrivateKey PrivateKeyFor3072BitParameters(
    const RsaSsaPssParameters& parameters, std::optional<int> id_requirement) {
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

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
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

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
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

RsaSsaPssPrivateKey PrivateKeyFor3072BitParameters2(
    const RsaSsaPssParameters& parameters, std::optional<int> id_requirement) {
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

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
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

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
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

RsaSsaPssPrivateKey PrivateKeyFor4096BitParameters(
    const RsaSsaPssParameters& parameters, std::optional<int> id_requirement) {
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

  absl::StatusOr<SecretData> d_sd =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_sd);
  RestrictedData d_data = RestrictedData(*d_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> prime_exponent_p_sd =
      ParseBigIntToFixedLength(prime_exponent_p, p.size());
  ABSL_CHECK_OK(prime_exponent_p_sd);
  RestrictedData prime_exponent_p_data =
      RestrictedData(*prime_exponent_p_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> prime_exponent_q_sd =
      ParseBigIntToFixedLength(prime_exponent_q, q.size());
  ABSL_CHECK_OK(prime_exponent_q_sd);
  RestrictedData prime_exponent_q_data =
      RestrictedData(*prime_exponent_q_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> q_inverse_sd =
      ParseBigIntToFixedLength(q_inverse, p.size());
  ABSL_CHECK_OK(q_inverse_sd);
  RestrictedData q_inverse_data =
      RestrictedData(*q_inverse_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
                                 id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(p_data)
          .SetPrimeQ(q_data)
          .SetPrimeExponentP(prime_exponent_p_data)
          .SetPrimeExponentQ(prime_exponent_q_data)
          .SetPrivateExponent(d_data)
          .SetCrtCoefficient(q_inverse_data)
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return *private_key;
}

RsaSsaPssPrivateKey PrivateKeyFor4096BitParameters2(
    const RsaSsaPssParameters& parameters, std::optional<int> id_requirement) {
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
  std::string q;
  ABSL_CHECK(absl::WebSafeBase64Unescape(
      "vnrCYzg2WTyJGXXd7RN9QPnhhRn5IzMEjxGBsLnsEgdQL1xfDRzVg2W_8-gLNQsBmQseqF4m"
      "P4rfS2qZ6sEyVUhV0lXCJTu69yLkG4k8gcyZM1YAaLIm4UfUWbmnPvGvKrlqKzmp5AE4WnE6"
      "hgq9O2rZFX3WwlCPGFnLhHF9TVM6etCuknNOCFlWxAqfphJVXmgkfmclI4aOBs3CPmJSRTdD"
      "WhQpJMfEZrLMie8oHCMK5v4SOukkieODQH5tueWoWfj31uOmi--RRJRCAib-QSMEnDJOsNzM"
      "4LfuE4L7uQsD2Hqq1ZbSMr41LYPgoBusZk_6lI_85BmAa2gCnFDsqw",
      &q));
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

  RestrictedData p_data(p, InsecureSecretKeyAccess::Get());
  RestrictedData q_data(q, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> d_sd =
      ParseBigIntToFixedLength(d, (parameters.GetModulusSizeInBits() + 7) / 8);
  ABSL_CHECK_OK(d_sd);
  RestrictedData d_data = RestrictedData(*d_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> prime_exponent_p_sd =
      ParseBigIntToFixedLength(prime_exponent_p, p.size());
  ABSL_CHECK_OK(prime_exponent_p_sd);
  RestrictedData prime_exponent_p_data =
      RestrictedData(*prime_exponent_p_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> prime_exponent_q_sd =
      ParseBigIntToFixedLength(prime_exponent_q, q.size());
  ABSL_CHECK_OK(prime_exponent_q_sd);
  RestrictedData prime_exponent_q_data =
      RestrictedData(*prime_exponent_q_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<SecretData> q_inverse_sd =
      ParseBigIntToFixedLength(q_inverse, p.size());
  ABSL_CHECK_OK(q_inverse_sd);
  RestrictedData q_inverse_data =
      RestrictedData(*q_inverse_sd, InsecureSecretKeyAccess::Get());

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(parameters, BigInteger(public_modulus),
                                 id_requirement, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key.status());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(p_data)
          .SetPrimeQ(q_data)
          .SetPrimeExponentP(prime_exponent_p_data)
          .SetPrimeExponentQ(prime_exponent_q_data)
          .SetPrivateExponent(d_data)
          .SetCrtCoefficient(q_inverse_data)
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key.status());
  return *private_key;
}

// SHA256
const SignatureTestVector& CreateTestVector0() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "97db7e8f38015cb1d14530c0bf3a28dfdd61e7570f3fea2d2933ba0afbbe6358f7d0"
        "c39e9647fd27c9b441557dc3e1ce34f8664bfdf93a7b1af78650eae4ed61f16c8583"
        "058296019fe968e92bcf35f38cb85a32c2107a76790a95a715440da281d026172b8b"
        "6e043af417852988441dac5ea888c849668bdcbb58f5c34ebe9ab5d16f7fa6cff32e"
        "9ed6a65c58708d887af791a33f34f7fc2da8885a9c867d347c6f92996dcb24f99701"
        "d2b955bb66f38c057f4acd51ff02da59c3bc129593820552ca07825a7e9920c2668c"
        "8eb99f2a541d9ef34f34054fda0d8a792822cc00f3f274fa0fcbf3c6a32f9fb85cba"
        "8dc713941f92a7a4f082693a2f79ff8198d6";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// SHA512
const SignatureTestVector& CreateTestVector1() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5e48d54433a"
        "230ec189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15d67b858782"
        "afa5f9c67d3880275d67cd98c40064adf08d9a58f0badb5c47b88a06ed81a23f"
        "fb131380c2f3bbc16a9290d13d31df54e2061b2f0acb3629a3693f03b3f2004b"
        "451de3e1ae2861654d145a5723f102f65533598aa5bc8e40b67190386a45fe99"
        "bf17c4610b2edf2538878989cacffd57b4c27c82ab72d95f380e50f0282423d7"
        "59a6d06241cd88a817e3c967ff0e2dd1cbbacc9402ffee0acf41bbec54ea2bbe"
        "01edadf0382c8ab2a897580c1cdf4e412032a083d1e5d47a625a38aac8c552e1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Variant: TINK
const SignatureTestVector& CreateTestVector2() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
            .SetVariant(RsaSsaPssParameters::Variant::kTink)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "0199887766b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5"
        "e48d54433a230ec189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15"
        "d67b858782afa5f9c67d3880275d67cd98c40064adf08d9a58f0badb5c47b88a"
        "06ed81a23ffb131380c2f3bbc16a9290d13d31df54e2061b2f0acb3629a3693f"
        "03b3f2004b451de3e1ae2861654d145a5723f102f65533598aa5bc8e40b67190"
        "386a45fe99bf17c4610b2edf2538878989cacffd57b4c27c82ab72d95f380e50"
        "f0282423d759a6d06241cd88a817e3c967ff0e2dd1cbbacc9402ffee0acf41bb"
        "ec54ea2bbe01edadf0382c8ab2a897580c1cdf4e412032a083d1e5d47a625a38"
        "aac8c552e1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Variant: CRUNCHY
const SignatureTestVector& CreateTestVector3() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
            .SetVariant(RsaSsaPssParameters::Variant::kCrunchy)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "0099887766b21a035305dbe9119803932330dbfcc4ab11bf15f1b89b974e53e5"
        "e48d54433a230ec189da5f0c77e53fb0eb320fd36a9e7209ffc78759cc409c15"
        "d67b858782afa5f9c67d3880275d67cd98c40064adf08d9a58f0badb5c47b88a"
        "06ed81a23ffb131380c2f3bbc16a9290d13d31df54e2061b2f0acb3629a3693f"
        "03b3f2004b451de3e1ae2861654d145a5723f102f65533598aa5bc8e40b67190"
        "386a45fe99bf17c4610b2edf2538878989cacffd57b4c27c82ab72d95f380e50"
        "f0282423d759a6d06241cd88a817e3c967ff0e2dd1cbbacc9402ffee0acf41bb"
        "ec54ea2bbe01edadf0382c8ab2a897580c1cdf4e412032a083d1e5d47a625a38"
        "aac8c552e1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Variant: LEGACY
const SignatureTestVector& CreateTestVector4() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kLegacy)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "0099887766433065815d23c7beff4780228b0e6212d7cedd6998c5528bd5b0a3"
        "ce90066a4a1f76c703745c23b4f7d92a5c84871dc9e6b2800d2bebd3d651afa8"
        "6b1eb68924bacabc0699358417319f5f9f7b326e636457c6098676f61c549b25"
        "c40975ee5cefa4c3c2b7d5d81efa0a78e4c777908762a0348022d425aafcdc4f"
        "6ada902d359758ad75ae8988eb522ea11771c9d84fc9ffe6f3b317872335b1d4"
        "af5f60e40e1a0d2588cb6640383b5b193f094754c21250485eb9430b056bab0d"
        "781ba261bd6cf80ad520402b83bc30a81d9ce38b7de9844d7d1310696de099db"
        "f2b642cfca8edb6b098c71d50710668870f3e47b115ecf4a0933573c92027d73"
        "7647daa9f8";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// SaltLengthBytes: 64
const SignatureTestVector& CreateTestVector5() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(64)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "aa5310c40c83878e0116ccc09efda3be6a88c667c797e61b6831e109fd6b5fbe"
        "d9df08cf05711d79cb384164fc5ddfb0de10a5110053c2b073449603bb11994f"
        "c0847d929806d5034e24db0662df5c0963fbac1d214842c4de1d7f4bfb741d8a"
        "2866e24819e8073042d17bccef92bbcdc6b34ca052486d60d12e9d992cebaaca"
        "5df2d7ea31c08af4d35338cdaa460a0ee568ff2bdaab1d72d6a8360713d98a09"
        "23ae929cff9950fd48bf0fa05e4324f4f9561defbb8e2c4854122394dd55bda7"
        "40d57064956255e36c6c1cc1970947d630121df570ba577957dd23116e9bf4c2"
        "c826ec4b52223735dd0c355165485ff6652656aa471a190c7f40e26c85440fc8";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

}  // namespace

// ModulusSize: 3072 bits
// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_3072_test.json.
const SignatureTestVector& Create3072BitTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "472fbd55339ba14605d52ce16c8d44d1ef3842504f796bafc04584a9b2228a8c"
        "6ec2cbd688e768578f7b0ebc8b20d9094aec7c6e1f4a98af0cda14929b2b637c"
        "698cafd0ae8f74ee9d51e1322daf57fea9a662641d6943f3fcc5818ac33d857f"
        "8ec01421413f966d6f6ba20ab4a7a743d747bc87bb1735c45fbe6ae446d9ffff"
        "c89f4ca33f13c776daeab64d69f67c1947efc3362d45268270cd019a37893575"
        "9a7d1b8a59c96edf796627c37e081082609225cc814f7be6d467e5fd5a0120ed"
        "38d32de319b8fb9afdb124d011781c7145f25422e9cdd2d6c699291930bb3179"
        "7f3ac5c1a18e95b5ba5667282e884d60cc0f3d7c5948b611b775312b0738339d"
        "e00a179a725c210b84986091948d311e743d423d9f665fdf6485cbee1446743e"
        "83f788ac6083d17489ff44231dcedefa36576acd2309edd8c5cd57545817f63b"
        "dfe3a9e59d479a9e2fde0bb8df2c7001db0af3ab6881b6081f394b897209faa4"
        "81331fcac97ef6245146a21188b01f417abfee348bebacd737266088a92da3fb";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor3072BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from third_party/wycheproof/testvectors/rsa_pkcs1_3072_test.json
const SignatureTestVector& Create3072BitTestVector2() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(3072)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "165056f4f019fd589b4c6d88cd530d9bea824c2a1e49f3cf2be1c8da3d258e5f"
        "11d4e9049640ba56018b990203baeef138bddc4d527d58e17feb4a68d3ba6d5f"
        "ae15a9faaa37978120816f6682e85689c9c5846a57ee8baecebdf4244683b981"
        "0e09830ec1efadad5896a4ebc8e4f4dad6ea6ed6674149621c9ac1327ffadfcc"
        "3260a0afeffeba89f8603d181f2dde4b3952f625dbdc35e75b00f2218c70f6e0"
        "de16b8abe5b53dfb5da3b345c161ef7aa7619061d33b59613a6259288836efe0"
        "9771ce46c05fd7cc3199f6da0f3244e71aa4e017e07dac144b14ca4c533c8d58"
        "3200a726112b509a7eb407104f09011f883711efee58b109866b5a1572e803ac"
        "787b68e93e1a1eb053e53c5a5b98d37a5c74ec051f5fd54ed9026893d84dc72d"
        "31f1aa759173a62b6799c75686133705cfa82b50d2e2baa883956cf2ebd6037e"
        "0098e9a1b6b4ab2ddb6b01315191b92d29176cee44e228b252109326b5ec43ba"
        "5464e62c6a1d4fe7323dea2e0795b2397dbbc686a47e6e79f554eba1ef777586";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor3072BitParameters2(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// ModulusSize: 4096 bits
// From
// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/rsa_pkcs1_4096_test.json.
const SignatureTestVector& Create4096BitTestVector() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(48)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "a005e5032c84e75fdc60b915d8e02091047041895e8f942a29e47528c751bbc3"
        "245af49ac22c84d7935c781da8a8d21b22a39fc36c81e61b0c38516977818ec8"
        "1aacc8aac03c56a4dba99534eb984bcc1bc63798736b642c5390cdda545d5701"
        "622f628ebe252a620322f9883713cc0a711473535a68e380bcdc8bc9c6b3ba09"
        "53b07cf960394de289c4d1860bbf45ae9a7c43f89337d3275be877170c4f543c"
        "5e23f9538f8cf9f26975172bc837a31a768807e2292a142c270dc2d638e3c606"
        "f9e2acf8f009300cbd98cf5a25e0191f14f340ce4d6b366a980a3cbae0fc09dc"
        "56fad0f1ae994843cdfa61babc62e04ddb73af9b48a25ff1d9524925df7f42c7"
        "33536a3548211a91adfed46ebbd6a9b3dfe9b4b8f035e2ad2751bcef5f53e9ae"
        "8ef858b33d98d627403e58f927b2e63092e7a2f16d2f9905ea5a6d490cac658d"
        "462926b7473d084bf1a2b7b87d9f7e38b917fa92b2b2cbcdbd530f2204419c57"
        "c9bb64dd901010861d67088ce9035d4fb40a4321430176a5184dfef91b7b5db1"
        "39b58ba75a45245d6cea2ef02a1013652838f15d72e165194bfde10af65357d5"
        "722f7826a46a6321df8ebed4308a9c34a678f6c15894699c91fd0a8360a11bf9"
        "65efaa8e3700485e5ec08c5b2aa0ddb64798d59e9a01dec9b4b523219729cc14"
        "e930783185470eef374bc7d2e098f077b641505c56c22350d910df76cf901102";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor4096BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// Extracted from third_party/wycheproof/testvectors/rsa_pkcs1_4096_test.json
const SignatureTestVector& Create4096BitTestVector2() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(4096)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(48)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "820701ae167f2fa3f324d0023a3b65902d5eb3301feebbbb511fd0a7056d8859"
        "74ce5d4ba26ecf150a23afc5df20c7a1475afa90ad26b0c06e2ab18723423725"
        "ad038f1086f87dd9bbc03ecad5c072bf1c77c448be1f87b72ed7c13a76689e01"
        "a3475c8929837631ccf461d165b35387fe19b7731fd0103390289d2bd1d63cd0"
        "5695dae074435e6933d1a094a5328793b273dec3ad171b2cc95a3d2ec38c4911"
        "424097e78c947dac33ed6a757322a8d014aa01c400d716946499bb192c298aeb"
        "ab394b24669adb32a36883bbaa954b6fe6baaa68c2eb8b502d3db1150dff59f5"
        "6879cb4df2d610b6f5516a99b750866d641a75f288051ad4d283733821d736de"
        "4afba3035db1d894a0ff4b640424bae38e9de952cb699e9eccdc8ec4a3a0cdda"
        "645cba206eddbe2bed69cde0f87f16c1a7d335a2d4af4525f45abeb586c754db"
        "ce3b04e8ed32b751d3aa2d04498e44f8554dd5a8e2d96da95cd432937e3907e6"
        "3bfd4df861cb4c962d78ae068c561994353f1742e829f3b557f69be77760963f"
        "9fae1f688f0ff755322666a2530f1eef77a3557520c8efb12cfa6c1146a7c829"
        "52d5ac211263aff6a41ac1a66bdba9ac626bffad08411e8c8963014107797a7f"
        "ca939b4898c27cf52d43491b34a3efb26dd540ca49ddaf43ee877383f9f58aa1"
        "ee4be83329c05cc01101e48016af9ef1d5a411073f396e61f5af9a9efcf9a9c1";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor4096BitParameters2(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

namespace {

// Sha384
const SignatureTestVector& CreateTestVector6() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha384)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha384)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(32)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "8c87ec23317b97c5d5e3692da3aa7037c183d757d0aa79ed1a2ccc46cde8397e"
        "2a8b231057034b2435813587314335bf308f9c930682e7575ec54968fdf15d9a"
        "689230ee2822338a97f08af3ce85b81f1c482617a2f3316b78b59ec3243541eb"
        "4e32bc3a33e20729f4019085dda89f7a6c4584ab9f4288755e65117f3f1dca29"
        "8ef9605804ee69a88bc7d7addb99b9dbee9f858d1f7df01f0b12fa9a9534bdea"
        "f7f197c1cafcb0853f32bfed7cb9495f073fcaa2d73eab5f9398b07300dbc9b8"
        "0dbff248106e6c8a52e564fd9de73e0122f576e5fa3c4bdb477663b616372568"
        "492b4f00b6261800b132a04a3dc735e44fc4ce9a72e3afaca5a0d50ea77388c9";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
}

// SaltLength: 0
const SignatureTestVector& CreateTestVector7() {
  static const absl::NoDestructor<SignatureTestVector> test_vector([]() {
    absl::StatusOr<RsaSsaPssParameters> parameters =
        RsaSsaPssParameters::Builder()
            .SetModulusSizeInBits(2048)
            .SetPublicExponent(kF4)
            .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
            .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
            .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
            .SetSaltLengthInBytes(0)
            .Build();
    ABSL_CHECK_OK(parameters.status());
    constexpr std::string_view kSignature =
        "5bfef53336a5148a2f880e28c92c71fa0523707390d075d7608a8eeab44cff51"
        "66946850f5818b00e4876922bf7cc0fedfdc1f8e265200c4c10e41686f62f8a6"
        "21b8ca2771106deb28fa9b0ec2b2687f106b8f68695dddc0b80dc15bec32e7ad"
        "2de73edb2789a8222866521230f2795b6c74de777050f02a0315776855f4bb1e"
        "063c93ef8d1c4a91abe393017b0cfa09548f6f5bfd565d02bdce2116ffca232e"
        "de6f4e869aac226f703ae0ef739fe926f0f15f916a7fa17b407118d9a5435379"
        "4835c224fa8c7b9213771526a7acb7575ddbd4ea3aaad6c827a5d1378773a455"
        "6763ed1442fddc76e29585c9d1992d42a8b730e744e44f3bfe5ddddc47b5d728";
    return SignatureTestVector(
        std::make_unique<RsaSsaPssPrivateKey>(
            PrivateKeyFor2048BitParameters(*parameters, std::nullopt)),
        HexDecodeOrDie(kSignature), HexDecodeOrDie("aa"));
  }());
  return *test_vector;
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
