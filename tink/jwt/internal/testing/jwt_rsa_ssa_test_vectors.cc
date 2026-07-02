// Copyright 2026 Google LLC
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

#include "tink/jwt/internal/testing/jwt_rsa_ssa_test_vectors.h"

#include <string>

#include "absl/base/no_destructor.h"
#include "absl/log/absl_check.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

namespace {

std::string DecodeOrDie(absl::string_view base64_string) {
  std::string dest;
  ABSL_CHECK(absl::WebSafeBase64Unescape(base64_string, &dest));
  return dest;
}

RsaSsaTestVector CreateVector1() {
  // RFC 7517 Appendix C.1
  return RsaSsaTestVector{
      /*n=*/DecodeOrDie(
          "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMSQRyO125Gp-"
          "TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom-QFcNP8Sjg086MwoqQU_"
          "LYywlAGZ21WSdS_"
          "PERyGFiNnj3QQlO8Yns5jCtLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-"
          "AqWS9zIQ2ZilgT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-"
          "Os6U15_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q"),
      /*e=*/std::string("\x01\x00\x01", 3),
      /*d=*/
      DecodeOrDie(
          "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_"
          "jn1DnfTuMdSNprTeaSTyWfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_"
          "IhUJtfri7bAXYEReWaCl3hdlPKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8"
          "dWBo4_PMaenNnPiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMq"
          "ADC6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1yX8C1EWme"
          "RDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ"),
      /*p=*/
      DecodeOrDie(
          "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-PIHfQP0FkxXV"
          "rx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk31s0Q8UK96E3_"
          "OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws"),
      /*q=*/
      DecodeOrDie(
          "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0c6Iedis4S7B"
          "_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV8CLCYKrYl52ziqK0E_"
          "ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s"),
      /*dp=*/
      DecodeOrDie(
          "KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_"
          "MOzqYAJMcLMZtbUtwKqvVDq3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_"
          "HgMXK_lhqigI4y_kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRV"
          "iD6c"),
      /*dq=*/
      DecodeOrDie(
          "AvfS0-"
          "gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkbN9GQTB9yqpDoYaN0"
          "6H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3KRbBymXxkb5qwUpX5ELD5xFc6Fe"
          "iafWYY63TmmEAu_lRFCOJ3xDea-ots"),
      /*q_inv=*/
      DecodeOrDie(
          "lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmUqqabu9V0-"
          "Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm-Fp0oYu_neotgQ0hzbI5"
          "gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8")};
}

RsaSsaTestVector CreateVector2() {
  // RFC 7515 Appendix A.2
  return RsaSsaTestVector{
      /*n=*/DecodeOrDie(
          "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-"
          "Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_"
          "YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-"
          "bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-"
          "UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_"
          "I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb5"
          "4h4FRWyuXpoQ"),
      /*e=*/std::string("\x01\x00\x01", 3),
      /*d=*/
      DecodeOrDie(
          "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_"
          "GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUC"
          "gu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_"
          "V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO"
          "1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_"
          "RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"),
      /*p=*/
      DecodeOrDie(
          "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_"
          "5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQ"
          "n7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGU"
          "c"),
      /*q=*/
      DecodeOrDie(
          "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYs"
          "p1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv"
          "5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc"),
      /*dp=*/
      DecodeOrDie(
          "BwKfV3Akq5_MFZDFZCnW-wzl-"
          "CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6"
          "HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1Xsm"
          "vkxHQAdYo0"),
      /*dq=*/
      DecodeOrDie(
          "h_96-mK1R_"
          "7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2"
          "oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m"
          "6_pbLBSp3nssTdlqvd0tIiTHU"),
      /*q_inv=*/
      DecodeOrDie(
          "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScG"
          "Lq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYa"
          "wBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U")};
}

RsaSsaTestVector CreateVector3072() {
  // From Wycheproof rsa_pkcs1_3072_test.json
  return RsaSsaTestVector{
      /*n=*/DecodeOrDie(
          "ANyPeIBnLwz51jYXqKWL3ScaEJut2g-oJvlLinlVJrakmoBWTMq6ipSRqTWlPt6uHZ"
          "p7VGPZ4u8-4M57_11LbIFHtcBzwvIgUV1THVWjZoem3jw0d1wvFRkawKdC1zQiKMjZ"
          "EP5rvKQ5U5xIXevL0O4OS64xdQO4PO6BAKx7tFh0Z8vENzxL2i7t98QWMeUJIrWA9b"
          "zoHSSyCMq80tdfz-mfdbST3_xcm9mQ9_w78u_jkv7K428-TvRFbBtd6ZzHRRczqRC2"
          "g0th7CknTZhr43UsNQsToyfavAjfz2VlSZrSboU0RmM-rbKXDKlbz2vwX_28KoBDeN"
          "dphacfBvkJefn-9xbDaqYlpFte7fUIJaU-nZQ1sjyqueXGTTj9OnZ-GFrXcn1uFfnp"
          "urL0GE1kh2lduaJpjGcrLoI0ENvvHZP-QMnTV-6fx3-EneETY_WDr4zPUYHKGuuUTE"
          "IlFstAHpUJI-S9iBQ5-hCTx3WCv-GsWZNnRwC2Q0M54CRTFdhvyw"),
      /*e=*/std::string("\x01\x00\x01", 3),
      /*d=*/
      DecodeOrDie(
          "BQEgW9F7iNDWYm3Q_siYoP1_aPjd3MMU900WfEBJW5WKh-TtYyAuasaPT09LiOPse"
          "gfYV1enRYRot2aq2aQPdzN4VUCLKNFA51wuazYE6okHu9f46VeMJACuZF0o4t7vi_c"
          "Y4pzxL8y5L--YafQ67lvWrcIjhI0WnNbCfCdmZSdm_4GZOz4BWlU97O4P_cFiTzn42"
          "Wtu1dlQR8FXC1n6LrPWiN1eFKzJQHuAlPGLRpQkTrGtzWVdhz9X_5r25P7EcL4ja68"
          "7IMIECrNg11nItOYYv4vU4OxmmPG3LHFg7QUhyCtRdrYPtjUD0K4j9uL7emCTBbCvY"
          "hULkhrFP03omWZssB2wydi2UHUwFcG25oLmvzggTln3QJw4CMDlPyVJNVQKOBqWPCw"
          "ad8b5h_BqB6BXJobtIogtvILngjzsCApY1ysJ0AzB0kXPFY_0nMQFmdOvcZ3DAbSqf"
          "1sDYproU-naq-KE24bVxB0EARQ98rRZPvTjdHIJxSP1p_gPAtAR"),
      /*p=*/
      DecodeOrDie(
          "_sahC_xJtYoshQ6v69uZdkmpVXWgwXYxsBHLINejICMqgVua9gQNe_I9Jn5eBjBMM-"
          "BMhebUgUQvAQqXWLoINkpwA175npyY7rQxUFsq-2d50ckdDqL7CmXcOR557Np9Uv19"
          "1pkjsl365EjKzoKeusprPIo8tkqBgAYUQ0iVd4wg1imxJbafQpRfZrZE84QLz6b842"
          "EHQlbFCGPsyiznVrSp-36ZPQ8fpIssxIW36qYUBfvvFQ51Y8IVCBF2feD5"),
      /*q=*/
      DecodeOrDie(
          "3Z7BzubYqXGxZpAsRKTwLvN6YgU7QSiKHYc9OZy8nnvTBu2QZIfaL0m8HBgJwNTYgQ"
          "bWh5UY7ZJf62aq1f88K4NGbFVO2XuWq-9Vs7AjFPUNA4WgodikauA-j86RtBISDwoQ"
          "3GgVcPpWS2hzus2Ze2FrK9dzP7cjreI7wQidoy5QlYNDbx40SLV5-yGyQGINIEWNCP"
          "D5lauswKOY8KtqZ8n1vPfgMvsdZo_mmNgDJ1ma4_3zqqqxm68XY5RDGUvj"),
      /*dp=*/
      DecodeOrDie(
          "8b-0DNVlc5cay162WwzSv0UCIo8s7KWkXDdmEVHL_bCgooIztgD-cn_WunHp8eFeTV"
          "MmCWCQf-Ac4dYU6iILrMhRJUG3hmN9UfM1X9RCIq97Di7RHZRUtPcWUjSy6KYhiN_z"
          "ye8hyhwW9wqDNhUHXKK5woZBOY_U9Y_PJlD3Uqpqdgy1hN2WnOyA4ctN_etr8au4Bm"
          "GJK899wopeozCcis9_A56K9T8mfVF6NzfS3hqcoVj-8XH4vaHppvA7CRKx"),
      /*dq=*/
      DecodeOrDie(
          "Pjwq6NNi3JKU4txx0gUPfd_Z6lTVwwKDZq9nvhoJzeev5y4nclPELatjK_CELKaY9g"
          "LZk9GG4pBMZ2q5Zsb6Oq3uxNVgAyr1sOrRAljgQS5frTGFXm3cHjdC2leECzFX6OlG"
          "ut5vxv5F5X87oKXECCXfVrx2HNptJpN1fEvTGNQUxSfLdBTjUdfEnYVk7TebwAhIBs"
          "7FCAbhyGcot80rYGISpDJnv2lNZFPcyec_W3mKSaQzHSY6IiIVS12DSkNJ"),
      /*q_inv=*/
      DecodeOrDie(
          "GMyXHpGG-GwUTRQM6rvJriLJTo2FdTVvtqSgM5ke8hC6-jmkzRq_"
          "qZszL96eVpVa8XlFmnI2pwC3_"
          "R2ICTkG9hMK58qXQtntDVxj5qnptD302LJhwS0sL5FIvAZp8WW4uIGHnD7VjUps1aPxG"
          "T6avSeEYJwB-5CUx8giUyrXrsKgiu6eJjCVrQQmRVy1kljH_"
          "Tcxyone4xgA0ZHtcklyHCUmZlDEbcv7rjBwYE0uAJkUouJpoBuvpb34u6McTztg")};
}

}  // namespace

const RsaSsaTestVector& GetRsa2048BitVector1() {
  static const absl::NoDestructor<RsaSsaTestVector> vector(CreateVector1());
  return *vector;
}

const RsaSsaTestVector& GetRsa2048BitVector2() {
  static const absl::NoDestructor<RsaSsaTestVector> vector(CreateVector2());
  return *vector;
}

const RsaSsaTestVector& GetRsa3072BitVector() {
  static const absl::NoDestructor<RsaSsaTestVector> vector(CreateVector3072());
  return *vector;
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
