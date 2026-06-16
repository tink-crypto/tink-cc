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

}  // namespace

const RsaSsaTestVector& GetRsa2048BitVector1() {
  static const absl::NoDestructor<RsaSsaTestVector> vector(CreateVector1());
  return *vector;
}

const RsaSsaTestVector& GetRsa2048BitVector2() {
  static const absl::NoDestructor<RsaSsaTestVector> vector(CreateVector2());
  return *vector;
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
