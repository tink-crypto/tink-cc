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

using ::crypto::tink::test::HexDecodeOrDie;

RsaSsaPkcs1PrivateKey PrivateKeyFor2048BitParameters(
    const RsaSsaPkcs1Parameters& parameters,
    absl::optional<int> id_requirement) {
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

RsaSsaPkcs1PrivateKey PrivateKeyFor4096BitParameters(
    const RsaSsaPkcs1Parameters& parameters,
    absl::optional<int> id_requirement) {
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

SignatureTestVector CreateTestVector0() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "3d10ce911833c1fe3f3356580017d159e1557e019096499950f62c3768c716bca418"
          "828dc140e930ecceffebc532db66c77b433e51cef6dfbac86cb3aff6f5fc2a488faf"
          "35199b2e12c9fe2de7be3eea63bdc960e6694e4474c29e5610f5f7fa30ac23b01504"
          "1353658c74998c3f620728b5859bad9c63d07be0b2d3bbbea8b9121f47385e4cad92"
          "b31c0ef656eee782339d14fd6350bb3756663c03cb261f7ece6e03355c7a4ecfe812"
          "c965f68890b2571916de0e2cd40814f9db9571065b5340ef7aa66d55a78cd62f4a1b"
          "d496623184a3d29dd886c1d1331754915bcbb243e5677ea7bb21a18d1ee22b6ba92c"
          "15a23ed6aede20abc29b290cc04fa0846027"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector1() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6358c"
          "78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa41b546c6751fd49b4ad"
          "986c9f38c3af9993a8466b91839415e6e334f6306984957784854bde60c3926cc103"
          "7f764d6182ea44d7398fbaeefcb8b3c84ba827700320d00ee28816ecb7ed90debf46"
          "183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05012f99d5df4c2b4a1a6c"
          "afab54f30ed9122531f4322ff11f8921c8b716827d5dd278c0dea49ebb67b188b825"
          "9ed820f1e750e45fd7767b9acdf30b47275739036a15aa11dfe030595e49d6c71ea8"
          "cb6a016e4167f3a4168eb4326d12ffed608c"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector2() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          /* Tink Prefix: */
          "0199887766"
          "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6358c"
          "78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa41b546c6751fd49b4ad"
          "986c9f38c3af9993a8466b91839415e6e334f6306984957784854bde60c3926cc103"
          "7f764d6182ea44d7398fbaeefcb8b3c84ba827700320d00ee28816ecb7ed90debf46"
          "183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05012f99d5df4c2b4a1a6c"
          "afab54f30ed9122531f4322ff11f8921c8b716827d5dd278c0dea49ebb67b188b825"
          "9ed820f1e750e45fd7767b9acdf30b47275739036a15aa11dfe030595e49d6c71ea8"
          "cb6a016e4167f3a4168eb4326d12ffed608c"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector3() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kCrunchy)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          /* Crunchy Prefix: */
          "0099887766"
          "67cbf2475fff2908ba2fbde91e5ac21901427cf3328b17a41a1ba41f955d64b6358c"
          "78417ca19d1bd83f360fe28e48c7e4fd3946349e19812d9fa41b546c6751fd49b4ad"
          "986c9f38c3af9993a8466b91839415e6e334f6306984957784854bde60c3926cc103"
          "7f764d6182ea44d7398fbaeefcb8b3c84ba827700320d00ee28816ecb7ed90debf46"
          "183abcc55950ff9f9b935df5ffaebb0f0b12a9244ac4fc05012f99d5df4c2b4a1a6c"
          "afab54f30ed9122531f4322ff11f8921c8b716827d5dd278c0dea49ebb67b188b825"
          "9ed820f1e750e45fd7767b9acdf30b47275739036a15aa11dfe030595e49d6c71ea8"
          "cb6a016e4167f3a4168eb4326d12ffed608c"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector4() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kLegacy)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, 0x99887766)),
      HexDecodeOrDie(
          "00998877668aece22c45c0db3db64e00416ed906b45e9c8ffedc1715cb3ea6cd9855"
          "a16f1c25375dbdd9028c79ad5ee192f1fa60d54efbe3d753e1c604ee7104398e2bae"
          "28d1690d8984155b0de78ab52d90d3b90509a1b798e79aff83b12413fa09bed089e2"
          "9e7107ca00b33be0797d5d2ab3033e04a689b63c52f3595245ce6639af9c0f0d3c3d"
          "be00f076f6dd0fd72d26579f1cffdb3218039de1b3de52b5626d2c3f840386904009"
          "be88b896132580716563edffa6ba15b29cf2fa1503236a5bec3f4beb5f4cc962677b"
          "4c1760d0c99dadf7704586d67fe95ccb312fd82e5c965041caf12afce18641e54a81"
          "2aa36faf14e2250a06b78ac111b1a2c8913f13e2a3d341"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector Create4096BitsTestVector() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor4096BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "122a08c6e8b9bf4cb437a00e55cf6ac96e216c4580af87e40be6227504e163c0c516"
          "b747d38a81f087f3878242008e4d0ef400d02f5bdc6629bb2f323241fcbbaa84aa17"
          "3324359bdf7e35becd68b3977367aeecf8cfb4a9497f883547c2f9e151ee47cddcc2"
          "5359ccf6ca28bef3daf116543343f63898ea514049620ddb91616e9ec4891ade53fe"
          "c4c06dc463a663e7c1008b2b9295a5478735e1fdb385a4fcc034853eb27602e96dfe"
          "a7f620b22085f3e345ed57f33e044aeb4450fe10346459b8fc4d306bf59038bd172d"
          "a6c32f4d6785c6e120a3da08988cf79a9e8a43fe97e6b64693776c209425a6d36cbf"
          "bf45ece68bffe7089bc5dc1c3ef265c0a88989ec279993a7e5c75f669768a1520791"
          "cc72f35268fa67654064d577d9d225da04c9694055df09cf3f14d8572a94c1793c32"
          "c0ecde034d24687a711d123f499f17f27fce41376100e854409ff647651633b1ec05"
          "0cf4893e8fea4a956e2ba0e177dcaf8176974e213963376b5fec2e4dac76f8ef5f23"
          "71d9f3124eea512b934e5b09d6528d26c2f0d3767af7d3320d1e73b6a93ac4404a88"
          "0603fdde06007a11f3ac554aceb0e40fff40702b6a5aa1fa492d630317ecc31aadd7"
          "9e6564c16a3f323f7fa4f58d4bfe27a09744f4ced12cddead3afa4dc6836afbbe238"
          "8dd933b8759d958d6334038eee7904bb907310726a0845ebddba81fb88db11c3853b"
          "251a"),
      HexDecodeOrDie("aa"));
}

SignatureTestVector CreateTestVector5() {
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha384)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(parameters.status());
  return SignatureTestVector(
      absl::make_unique<RsaSsaPkcs1PrivateKey>(
          PrivateKeyFor2048BitParameters(*parameters, absl::nullopt)),
      HexDecodeOrDie(
          "71ae1ecd20509a12627a876e2efcd67015659923b9e2564405673641d73615eb9376"
          "25db427b55c582b97172eeddabc247ee2f0f44652c8310d433f4cdbad3b558d26404"
          "14afc70725fe40849d2652d91413a9ce5ee2f234cae1fb1a35b8b3452b60ca33d38c"
          "6c84b2feaffff1c0f5be3deab76b3cdff154f76c18bfdbe18e0b62ea832986802e9a"
          "07eeeae3b367c551c6672cc64e1e9e13bed3352d6f8a109ebaf86a90a973939f4c6a"
          "7b4f0ff214228051bdfd1c00ed2dda804e168fa4247835b25a8d88a57b8e042c45ce"
          "dc00db2cd03f5bd4ec5647e90737e5325ce2fc3ecea2af569d1fb51a8332f4b526ba"
          "214b0b8d10d562ba2dccb0267c85098d8ff1"),
      HexDecodeOrDie("aa"));
}

}  // namespace

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
