// Copyright 2026 Google LLC
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

#include "tink/pem/signature_key_parser.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "tink/big_integer.h"
#include "tink/config/config_2026.h"
#include "tink/config/global_registry.h"
#include "tink/config/key_gen_config_2026.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ssl_util.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_private_key.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_config.h"
#include "tink/util/test_util.h"

namespace tink_pem {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::BigInteger;
using ::crypto::tink::Config2026;
using ::crypto::tink::ConfigGlobalRegistry;
using ::crypto::tink::EcdsaParameters;
using ::crypto::tink::EcdsaPrivateKey;
using ::crypto::tink::EcdsaPublicKey;
using ::crypto::tink::EcPoint;
using ::crypto::tink::Ed25519Parameters;
using ::crypto::tink::Ed25519PrivateKey;
using ::crypto::tink::Ed25519PublicKey;
using ::crypto::tink::GetPartialKeyAccess;
using ::crypto::tink::InsecureSecretKeyAccess;
using ::crypto::tink::KeyGenConfig2026;
using ::crypto::tink::KeyGenConfigGlobalRegistry;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetHandleBuilder;
using ::crypto::tink::KeyStatus;
using ::crypto::tink::MlDsaParameters;
using ::crypto::tink::MlDsaPrivateKey;
using ::crypto::tink::MlDsaPublicKey;
using ::crypto::tink::PublicKeySign;
using ::crypto::tink::PublicKeyVerify;
using ::crypto::tink::RestrictedData;
using ::crypto::tink::RsaSsaPkcs1Parameters;
using ::crypto::tink::RsaSsaPkcs1PrivateKey;
using ::crypto::tink::RsaSsaPkcs1PublicKey;
using ::crypto::tink::RsaSsaPssParameters;
using ::crypto::tink::RsaSsaPssPrivateKey;
using ::crypto::tink::RsaSsaPssPublicKey;
using ::crypto::tink::SecretData;
using ::crypto::tink::SignatureConfig;
using ::crypto::tink::internal::IsBoringSsl;
using ::crypto::tink::test::HexDecodeOrDie;
using ::testing::Eq;

// TODO: b/532411253 - Remove this macro.
#define TINK_ASSERT_OK_AND_ASSIGN(Type, var, expr) \
  absl::StatusOr<Type> var##_status_or = (expr);   \
  ASSERT_THAT(var##_status_or, IsOk());            \
  Type var = std::move(*var##_status_or)

// ======================= P-256 =======================

// openssl ecparam -genkey -name prime256v1 -noout
constexpr absl::string_view kP256PrivateKeyPem =
    R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIISF+3aOEJ0Uvh4hnU2AZSMwjg5AHbHeldyTjokDxJssoAoGCCqGSM49
AwEHoUQDQgAEFFXP1ZTUTfEl8f9kNjZ0DGzFmXIJH+5vqbjTiX1ZsODQtlUjjYwM
67/ed7H9pirRnMxr8lpOv1Y301l5gwlDYw==
-----END EC PRIVATE KEY-----
)";

// Obtained via: echo "<kP256PrivateKeyPem>" | openssl pkcs8 -topk8 -nocrypt
constexpr absl::string_view kP256Pkcs8PrivateKeyPem =
    R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghIX7do4QnRS+HiGd
TYBlIzCODkAdsd6V3JOOiQPEmyyhRANCAAQUVc/VlNRN8SXx/2Q2NnQMbMWZcgkf
7m+puNOJfVmw4NC2VSONjAzrv953sf2mKtGczGvyWk6/VjfTWXmDCUNj
-----END PRIVATE KEY-----
)";

// Obtained via: echo "<kP256Pkcs8PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kP256PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFFXP1ZTUTfEl8f9kNjZ0DGzFmXIJ
H+5vqbjTiX1ZsODQtlUjjYwM67/ed7H9pirRnMxr8lpOv1Y301l5gwlDYw==
-----END PUBLIC KEY-----
)";

// Extracted from kP256Pkcs8PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,128):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier ecPublicKey (1 2 840 10045 2 1)
//     ObjectIdentifier P-256 (1 2 840 10045 3 1 7)
//   OCTETSTRING, encapsulates
//     SEQUENCE
//       INTEGER 01
//       OCTETSTRING
//       8485fb768e109d14be1e219d4d806523308e0e401db1de95dc938e8903c49b2c [1]
//         BITSTRING
//         00041455cfd594d44df125f1ff643636740c6cc59972091fee6fa9b8d3897d59b0e0d0b655238d8c0cebbfde77b1fda62ad19ccc6bf25a4ebf5637d3597983094363
// NOLINTEND
constexpr absl::string_view kP256PubXHex =
    "1455cfd594d44df125f1ff643636740c6cc59972091fee6fa9b8d3897d59b0e0";
constexpr absl::string_view kP256PubYHex =
    "d0b655238d8c0cebbfde77b1fda62ad19ccc6bf25a4ebf5637d3597983094363";
constexpr absl::string_view kP256PrivHex =
    "8485fb768e109d14be1e219d4d806523308e0e401db1de95dc938e8903c49b2c";

// ======================= P-384 =======================

// openssl ecparam -genkey -name secp384r1 -noout
constexpr absl::string_view kP384PrivateKeyPem =
    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDACVM1YQO7BOw1ougj9vBR8IpBgRuyy/KJiUpS+dN6imqNw/YMJhdJ4
CZZE7PiRZ82gBwYFK4EEACKhZANiAARJsaeFNygcgZhOAAkvBMIsYQysKrp6PemS
v2rSIwXS1UUBh1ftgjxkMzThjZWy5kLSqFFEXF2gvw1UPqrV/5hjRIPFSdlgRSQx
Ie1tXJumTatlam0l4BiwHE06s/FziYk=
-----END EC PRIVATE KEY-----
)";

// Obtained via: echo "<kP384PrivateKeyPem>" | openssl pkcs8 -topk8 -nocrypt
constexpr absl::string_view kP384Pkcs8PrivateKeyPem =
    R"(-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDACVM1YQO7BOw1ougj9
vBR8IpBgRuyy/KJiUpS+dN6imqNw/YMJhdJ4CZZE7PiRZ82hZANiAARJsaeFNygc
gZhOAAkvBMIsYQysKrp6PemSv2rSIwXS1UUBh1ftgjxkMzThjZWy5kLSqFFEXF2g
vw1UPqrV/5hjRIPFSdlgRSQxIe1tXJumTatlam0l4BiwHE06s/FziYk=
-----END PRIVATE KEY-----
)";

// Obtained via: echo "<kP384Pkcs8PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kP384PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAESbGnhTcoHIGYTgAJLwTCLGEMrCq6ej3p
kr9q0iMF0tVFAYdX7YI8ZDM04Y2VsuZC0qhRRFxdoL8NVD6q1f+YY0SDxUnZYEUk
MSHtbVybpk2rZWptJeAYsBxNOrPxc4mJ
-----END PUBLIC KEY-----
)";

// Extracted from kP384Pkcs8PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,128):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier ecPublicKey (1 2 840 10045 2 1)
//     ObjectIdentifier secp384r1 (1 3 132 0 34)
//   OCTETSTRING, encapsulates
//     SEQUENCE
//       INTEGER 01
//       OCTETSTRING
//       0254cd5840eec13b0d68ba08fdbc147c22906046ecb2fca2625294be74dea29aa370fd830985d278099644ecf89167cd
//       [1]
//         BITSTRING
//         000449b1a78537281c81984e00092f04c22c610cac2aba7a3de992bf6ad22305d2d545018757ed823c643334e18d95b2e642d2a851445c5da0bf0d543eaad5ff98634483c549d96045243121ed6d5c9ba64dab656a6d25e018b01c4d3ab3f1738989
// NOLINTEND
constexpr absl::string_view kP384PubXHex =
    "49b1a78537281c81984e00092f04c22c610cac2aba7a3de992bf6ad22305d2d54501"
    "8757ed823c643334e18d95b2e642";
constexpr absl::string_view kP384PubYHex =
    "d2a851445c5da0bf0d543eaad5ff98634483c549d96045243121ed6d5c9ba64dab65"
    "6a6d25e018b01c4d3ab3f1738989";
constexpr absl::string_view kP384PrivHex =
    "0254cd5840eec13b0d68ba08fdbc147c22906046ecb2fca2625294be74dea29aa370"
    "fd830985d278099644ecf89167cd";

// ======================= P-521 =======================

// openssl ecparam -genkey -name secp521r1 -noout
constexpr absl::string_view kP521PrivateKeyPem =
    R"(-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB8ZE6khJxwGaGSCpR2/LIU677zGKysj1HOkyBjVcOVVZnQu3Z8F0F
Mvc9QMEdPTHDc05EcMwEka2RGiCfHojc1xKgBwYFK4EEACOhgYkDgYYABAHQnuLz
POYB2FlLCeZo4SincIznUu9YnRosQFUj2wtooMtYYDWbEsU3H8Ri9BQjOcp/8lUI
M/CmSIeVHdtk59E51QG0XOEoBK/PF/vWByjTYtR4e3UNVh5SFE/VF4B92qKzlr7Z
mCJ6VpbZyZehzwtvGjckziXHOW3C6mLEvfRnBhkW4w==
-----END EC PRIVATE KEY-----
)";

// Obtained via: echo "<kP521PrivateKeyPem>" | openssl pkcs8 -topk8 -nocrypt
constexpr absl::string_view kP521Pkcs8PrivateKeyPem =
    R"(-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB8ZE6khJxwGaGSCpR
2/LIU677zGKysj1HOkyBjVcOVVZnQu3Z8F0FMvc9QMEdPTHDc05EcMwEka2RGiCf
Hojc1xKhgYkDgYYABAHQnuLzPOYB2FlLCeZo4SincIznUu9YnRosQFUj2wtooMtY
YDWbEsU3H8Ri9BQjOcp/8lUIM/CmSIeVHdtk59E51QG0XOEoBK/PF/vWByjTYtR4
e3UNVh5SFE/VF4B92qKzlr7ZmCJ6VpbZyZehzwtvGjckziXHOW3C6mLEvfRnBhkW
4w==
-----END PRIVATE KEY-----
)";

// Obtained via: echo "<kP521Pkcs8PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kP521PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB0J7i8zzmAdhZSwnmaOEop3CM51Lv
WJ0aLEBVI9sLaKDLWGA1mxLFNx/EYvQUIznKf/JVCDPwpkiHlR3bZOfROdUBtFzh
KASvzxf71gco02LUeHt1DVYeUhRP1ReAfdqis5a+2ZgielaW2cmXoc8Lbxo3JM4l
xzltwupixL30ZwYZFuM=
-----END PUBLIC KEY-----
)";

// Extracted from kP521Pkcs8PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,256):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier ecPublicKey (1 2 840 10045 2 1)
//     ObjectIdentifier secp521r1 (1 3 132 0 35)
//   OCTETSTRING, encapsulates
//     SEQUENCE
//       INTEGER 01
//       OCTETSTRING
//       01f1913a921271c06686482a51dbf2c853aefbcc62b2b23d473a4c818d570e55566742edd9f05d0532f73d40c11d3d31c3734e4470cc0491ad911a209f1e88dcd712
//       [1]
//         BITSTRING
//         000401d09ee2f33ce601d8594b09e668e128a7708ce752ef589d1a2c405523db0b68a0cb5860359b12c5371fc462f4142339ca7ff2550833f0a64887951ddb64e7d139d501b45ce12804afcf17fbd60728d362d4787b750d561e52144fd517807ddaa2b396bed998227a5696d9c997a1cf0b6f1a3724ce25c7396dc2ea62c4bdf467061916e3
// NOLINTEND
constexpr absl::string_view kP521PubXHex =
    "01d09ee2f33ce601d8594b09e668e128a7708ce752ef589d1a2c405523db0b68a0cb"
    "5860359b12c5371fc462f4142339ca7ff2550833f0a64887951ddb64e7d139d5";
constexpr absl::string_view kP521PubYHex =
    "01b45ce12804afcf17fbd60728d362d4787b750d561e52144fd517807ddaa2b396be"
    "d998227a5696d9c997a1cf0b6f1a3724ce25c7396dc2ea62c4bdf467061916e3";
constexpr absl::string_view kP521PrivHex =
    "01f1913a921271c06686482a51dbf2c853aefbcc62b2b23d473a4c818d570e555667"
    "42edd9f05d0532f73d40c11d3d31c3734e4470cc0491ad911a209f1e88dcd712";

TEST(PemParserEcdsaTest, PemToSignaturePrivateKeyEcdsaSuccessAndSignVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(EcdsaPrivateKey, priv_key,
                            PemToEcdsaPrivateKey(kP256PrivateKeyPem, params,
                                                 InsecureSecretKeyAccess::Get(),
                                                 GetPartialKeyAccess()));
  EXPECT_EQ(priv_key.GetPublicKey().GetParameters(), params);

  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              priv_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "some test message to sign";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle,
      handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()));

  // Verify using the public key obtained from the private key.
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeyVerify>, verifier,
      pub_handle->GetPrimitive<PublicKeyVerify>(ConfigGlobalRegistry()));
  EXPECT_THAT(verifier->Verify(signature, kMessage), IsOk());

  // Use the public key obtained from PEM.
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPublicKey, pub_key_from_pem,
      PemToEcdsaPublicKey(kP256PublicKeyPem, params, GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, pub_handle_from_pem,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              pub_key_from_pem, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>, verifier_from_pem,
                            pub_handle_from_pem.GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_pem->Verify(signature, kMessage), IsOk());
}

TEST(PemParserEcdsaTest, PemToSignaturePrivateKeyFailsForPublicKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)

          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToEcdsaPrivateKey(kP256PublicKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcdsaTest, PemToSignaturePublicKeyFailsForPrivateKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)

          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToEcdsaPublicKey(kP256PrivateKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcdsaTest, PemToSignatureKeyMismatchedParamsCurveP384P256_Fails) {
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToEcdsaPrivateKey(kP384PrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      PemToEcdsaPublicKey(kP384PublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcdsaTest, PemToSignatureKeyMismatchedParamsCurveP256P384_Fails) {
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToEcdsaPrivateKey(kP256PrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      PemToEcdsaPublicKey(kP256PublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcdsaTest, ParserToKeysetDifferentParamsSuccessAndSignVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params1,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kIeeeP1363)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params2,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(EcdsaPrivateKey, priv_key1,
                            PemToEcdsaPrivateKey(kP521PrivateKeyPem, params1,
                                                 InsecureSecretKeyAccess::Get(),
                                                 GetPartialKeyAccess()));

  TINK_ASSERT_OK_AND_ASSIGN(EcdsaPrivateKey, priv_key2,
                            PemToEcdsaPrivateKey(kP256PrivateKeyPem, params2,
                                                 InsecureSecretKeyAccess::Get(),
                                                 GetPartialKeyAccess()));

  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              priv_key1, KeyStatus::kEnabled, /*is_primary=*/true))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              priv_key2, KeyStatus::kEnabled, /*is_primary=*/false))
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "some test message to sign";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle,
      handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()));

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeyVerify>, verifier,
      pub_handle->GetPrimitive<PublicKeyVerify>(ConfigGlobalRegistry()));
  EXPECT_THAT(verifier->Verify(signature, kMessage), IsOk());
}

TEST(PemParserEcdsaTest, PemToSignaturePrivateKeyRsaFails) {
  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaParameters, params,
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build());

  constexpr absl::string_view kRsaPrivateKeyPem = R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5KzIhafMFR4YQ
u3RqKmdpk4oOlQUluM6TFuUKUGgGTuBYx3/hwSFuAkEzrA4oBLaiz8nKrYCIxS7A
FW8xJB4eIGvGB2fzixfZ8gjdRWHdCRXbZpAriPlh3zsqii11XZUMgBSWSYdT3v1/
t42h1oy4DsgxpjeuuO1gETkqpfk4V3RYRm/9Nt/1DVKxiR7IdVcK+3hHQ9stx7b3
UIwQrEuBfHPaGwp2vbA738dWYShaf7pxN3s0/GeoB/m7dpAc57r8Cu1PlBiGnVt5
82tkQCBQJW0MbIQVK4YPvz4aDWZofu+puehiS8bSjTXkkU/pg7mYILUbhrcJDHvi
FF9dRiRfAgMBAAECggEABBtlKg1dJCM8YgEGYzE7+43kl5ybV9IL77Wn46ngF/1T
FItrcE85HDHvAeP+QsnExnYW/II+Qf2Kb+nWl+xvjpOBg6VRm1R2dV5DVat4Spxg
LVTOopvDJdyU318S0XH/hrhAiXGc3GT4LAdrzy8gp+RycRRF7LL4inm9uHU99dxQ
8XjIt706Xwfbd4RHTF7eDq2ZGc7IyNkgsZZ47iTf+0z/VxC4zf/LdCKxmhcWuguq
AcUsUGfYuT+cKq8rx32/m3TJpwq7b2KF/+5buXxzuwqduSNCnSIFjvm5ABSJ2DvH
BL+sUKE9Kj6dInfOnjMXiK6GUggRPwYF8i0MfkyfQQKBgQD+EMI9FgnHrqc0XE2I
Oug2o88n7/FPicGAlMkAADeKcEfnWt8OiUDSiVMowzItE9jtlyZUt7CVWH0hLRKc
JLOszALWEQJIYHSI7jmRp+srXFHeBcJcHf4MNcRNOeeb11I0HQ5XfWrjk1mHws6u
yGgXSwpZwJYPBU/Dp8PMuyML2QKBgQC6lCOVk2z4Pz5esJNKW29kvro7B70qoZL5
Lq/2VDBURJligBGZPz19nyaW+DjXSizrdFjHZDBuOclLHqOf87UhRxF55gWcxgId
fZLiW4IcEZBcEQ7v9lx7geihGF/ICTXho3F4455aQBYPuFkxMJYvp72hR8fsyfWc
J8DQ4Z+m9wKBgQDbRLluoQOFy41Q2kyrwzNAXPXfYOzhmWFgSIiEsKs+lpLn7/xM
flZsncoghv5Z+yQgQW/6c6I58mnj5ROHoQFUo6na+EkBEAXjW75hoAuNm5qoRE4u
1E+6V/j4MX5beGTgxybmiT5j9HqzeYSJQjrbx47CUTzw78Ocd8C7g9LGWQKBgCXl
8VRwnbHPJtwVAdYYvIe6NhnHeKUwLKpw0U03zJlRVdasLObz8YmSykPgJ6uTZYxu
FZpqv2ukUT7w+kuDNUeNJ/+auYker09OMofIDqWk663HyUD0ydRMjvQp/0qilE9A
48uqcH/khJas23EibV9As0QPUIzIeRs+9+t16PgBAoGAAzy0JnDIhjtgaN3624Gr
P1K0iupNKtjYei7VESnNsQW4t4pB5qb6xbJKPjN03dbuz0GGh965CjSA/VCXeElZ
pYInUjQfa64FCokCareJ8tFNurW2HUGtinQHTspN2fjd4n7nImXiRWIo0gmJ1AxV
SpBldzylZq4R3Ez3SY5RxHM=
-----END PRIVATE KEY-----)";
  EXPECT_THAT(PemToEcdsaPrivateKey(kRsaPrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

struct PemParserEcdsaTestParams {
  std::string test_name;
  EcdsaParameters parameters;
  absl::string_view pub_x_hex;
  absl::string_view pub_y_hex;
  absl::string_view priv_hex;
  // SEC1 PEM format (RFC 5915).
  absl::string_view sec1_pem;
  // PKCS#8 PEM format (RFC 5208 / RFC 5958 "BEGIN PRIVATE KEY").
  absl::string_view pkcs8_pem;
  absl::string_view public_key_pem;
};

using PemParserEcdsaTest = testing::TestWithParam<PemParserEcdsaTestParams>;

EcdsaPrivateKey CreateEcdsaPrivateKeyFromTestVector(
    const PemParserEcdsaTestParams& params) {
  std::string pub_x_bytes;
  ABSL_CHECK(absl::HexStringToBytes(params.pub_x_hex, &pub_x_bytes));
  std::string pub_y_bytes;
  ABSL_CHECK(absl::HexStringToBytes(params.pub_y_hex, &pub_y_bytes));
  std::string priv_bytes;
  ABSL_CHECK(absl::HexStringToBytes(params.priv_hex, &priv_bytes));

  BigInteger pub_x_int(pub_x_bytes);
  BigInteger pub_y_int(pub_y_bytes);
  EcPoint public_point(pub_x_int, pub_y_int);
  absl::StatusOr<EcdsaPublicKey> public_key = EcdsaPublicKey::Create(
      params.parameters, public_point,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, RestrictedData(priv_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

TEST_P(PemParserEcdsaTest, PemToSignaturePrivateKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  PemParserEcdsaTestParams params = GetParam();
  EcdsaPrivateKey private_key = CreateEcdsaPrivateKeyFromTestVector(params);

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPrivateKey, parsed_key,
      PemToEcdsaPrivateKey(params.pkcs8_pem, params.parameters,
                           InsecureSecretKeyAccess::Get(),
                           GetPartialKeyAccess()));
  EXPECT_EQ(parsed_key, private_key);
}

TEST_P(PemParserEcdsaTest, PemToSignaturePublicKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  PemParserEcdsaTestParams params = GetParam();
  EcdsaPrivateKey private_key = CreateEcdsaPrivateKeyFromTestVector(params);

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPublicKey, parsed_public_key,
      PemToEcdsaPublicKey(params.public_key_pem, params.parameters,
                          GetPartialKeyAccess()));
  EXPECT_EQ(parsed_public_key, private_key.GetPublicKey());
}

TEST_P(PemParserEcdsaTest, SignAndVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  PemParserEcdsaTestParams params = GetParam();

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPrivateKey, private_key,
      PemToEcdsaPrivateKey(params.pkcs8_pem, params.parameters,
                           InsecureSecretKeyAccess::Get(),
                           GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, private_handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              private_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      private_handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPublicKey, public_key,
      PemToEcdsaPublicKey(params.public_key_pem, params.parameters,
                          GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, public_handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              public_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeyVerify>, verifier,
      public_handle.GetPrimitive<PublicKeyVerify>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "test message";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));
  EXPECT_THAT(verifier->Verify(signature, kMessage), IsOk());
}

TEST_P(PemParserEcdsaTest, PemToSignaturePrivateKeySec1Legacy) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  PemParserEcdsaTestParams params = GetParam();
  EcdsaPrivateKey private_key = CreateEcdsaPrivateKeyFromTestVector(params);

  TINK_ASSERT_OK_AND_ASSIGN(
      EcdsaPrivateKey, sec1_key,
      PemToEcdsaPrivateKey(params.sec1_pem, params.parameters,
                           InsecureSecretKeyAccess::Get(),
                           GetPartialKeyAccess()));
  EXPECT_EQ(sec1_key, private_key);
}

std::vector<PemParserEcdsaTestParams> GetPemParserEcdsaTestParams() {
  absl::StatusOr<EcdsaParameters> p256_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(p256_params);
  absl::StatusOr<EcdsaParameters> p384_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(p384_params);
  absl::StatusOr<EcdsaParameters> p521_params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP521)
          .SetHashType(EcdsaParameters::HashType::kSha512)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
  ABSL_CHECK_OK(p521_params);
  return {
      PemParserEcdsaTestParams{
          /*test_name=*/"P256",
          /*parameters=*/*p256_params,
          /*pub_x_hex=*/kP256PubXHex,
          /*pub_y_hex=*/kP256PubYHex,
          /*priv_hex=*/kP256PrivHex,
          /*sec1_pem=*/kP256PrivateKeyPem,
          /*pkcs8_pem=*/kP256Pkcs8PrivateKeyPem,
          /*public_key_pem=*/kP256PublicKeyPem,
      },
      PemParserEcdsaTestParams{
          /*test_name=*/"P384",
          /*parameters=*/*p384_params,
          /*pub_x_hex=*/kP384PubXHex,
          /*pub_y_hex=*/kP384PubYHex,
          /*priv_hex=*/kP384PrivHex,
          /*sec1_pem=*/kP384PrivateKeyPem,
          /*pkcs8_pem=*/kP384Pkcs8PrivateKeyPem,
          /*public_key_pem=*/kP384PublicKeyPem,
      },
      PemParserEcdsaTestParams{
          /*test_name=*/"P521",
          /*parameters=*/*p521_params,
          /*pub_x_hex=*/kP521PubXHex,
          /*pub_y_hex=*/kP521PubYHex,
          /*priv_hex=*/kP521PrivHex,
          /*sec1_pem=*/kP521PrivateKeyPem,
          /*pkcs8_pem=*/kP521Pkcs8PrivateKeyPem,
          /*public_key_pem=*/kP521PublicKeyPem,
      },
  };
}

INSTANTIATE_TEST_SUITE_P(
    PemParserEcdsaTest, PemParserEcdsaTest,
    testing::ValuesIn(GetPemParserEcdsaTestParams()),
    [](const testing::TestParamInfo<PemParserEcdsaTestParams>& info) {
      return info.param.test_name;
    });

// ================== ML-DSA ==================

// Obtained via:  openssl genpkey -algorithm ML-DSA-44 \
//                  -provparam ml-dsa.output_formats=seed-only
constexpr absl::string_view kMlDsa44PrivateKeyPem =
    R"(
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMRBCKAILnZjeL2q/BhNdr13gsNZwLAB4vZUDY5E7mq
rzVp1Noy
-----END PRIVATE KEY-----)";

// Extracted from kMlDsa44PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,10000):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier (2 16 840 1 101 3 4 3 17)
//   OCTETSTRING, encapsulates
//     [0] b9d98de2f6abf06135daf5de0b0d6702c0078bd950363913b9aaaf3569d4da32
// NOLINTEND
constexpr absl::string_view kMlDsa44ExpectedSeedBytesHex =
    "b9d98de2f6abf06135daf5de0b0d6702c0078bd950363913b9aaaf3569d4da32";

// Obtained via: echo "<kMlDsa44PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kMlDsa44PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhAEY3nTdaxXN8Xdh1XkCNRSdZSQWktFgLpnnn
mIc40tZ9uh5bGKaFrTwKJezB1Hhvyy6N0P1M8RtZ4PZRlSc7QJhAEWnydPcvrtSI
b6GsU0t5QhVb60/5P2h2ryH3Z9rAqnvtwteR0hPzkN+e7GT93x+ZLOgQ1NC3UWKD
4gwr4nUQUcTIkPpAUzW3pfrYxaoU1ARhp1z9fukEvOInWIzZ9yhS5dDIXZYW1GCm
gzKg9vxW/OgcdS9uOZvKSuWZbDeCPzpjrwtyv+DqGETRoGxXzIWgNdVVg3VOxP5i
Osxk60UdVyBo4WoYvS7I/Rhe+HqKvC/NjYJUiYjDMZSmI0Ort1cixtZo/JbPubVC
UKtQ1raUyPZuHZTld16dVSi8Kqtfu4tKc9sE9ImayFJd2gegPuQjVgzPCRryzQmY
jx2BaVNWTR0yUA437p2Bab2TbugKMEycYIKWtrUY91EeY/QarZrWp0KWCjHx0APF
3kLFvp1t5UBmEgGoOAcjqWeBjq/gFkkdtfA0l1QptYtunpmVjQ8as6B3wiz4h/6E
ywYKDNlhcpE9P+zHVM5lySShSdRP/S+AvqGEnBFjDefu/VeHmMgDbYxwNOi3PsLV
C1PGxVpS6l8wywb2s+fkWBlrtcGAbcvC/Pzwdf3XxIavy6pBvcu/9/i9J4EdYn//
GvegalAFcMFRbW0Cxwf3Z12vlmw1XaRZxntG8UeEuk0lOuI9CPE4RjhU6BtuiRsE
P0iGgsLZ9QOIfBi3RnBem3ksmipaNrD0MnwoI2W4Gxx1fZ5swdzY4NrRuQ9eXs4k
Q002Yrzqc/yUmivV+o+39yTw4qUy7/e5tLJK6HYm9P6nNMtrf1YjsDDROo6RivES
ziyR4CDYfYimIH2Ic8UkG1hRRx96MFFj1if77uH/4vf9iVh8LsifeE6kDD4lnCcB
/Js9W7Y9oe40Qb6J64B/tPxfViEkUGVLH81QHfgwpPcaxK0jJWEuqrj8WvIUwuEp
c4RtaSPA3DugUnuxrC2K17WHyFWGdOen+76Gp2OlpdCGJbFY3EmhbVjMRpYLz6BH
zjnZwHMKYjDwHfJjwA45s23lKhK17KTEYnHyxhd/fAC896ZNbn6g0N4CYUXcskww
usbksecsr/CrCzdpTxaiPY5Vz3CaS1qW/N52rbiYL38xeQXICKUolHJK89/pUOoo
gD5a3uZDShRLUpsTO1tcflfPTzTpt80FNz72PKneNirY+ho6j32hgYP23a6FyzmY
Qj77gTcQrEd+uGSRZh8UO0/VOSwVISEBY1YAei5gMC0tCIHBpav8WCiUZ4oaERB0
Yu2UJSOo3/oTYrTRubpkkjo4fMktG4EKGONqU4lXcZoPTflc/UIG+osyPSA77CQa
K/FFYW/+xHTgEQkG/TkeWckaChVMgICiMr5KWStVva5GDbR1/YGEbHeRBluuzXyb
IyFWY8ik7ty5jKdzbxgFfwdLRBx2wG4+VwhtaZTHsmJpAg3cvcVC7+gBD+T3d7Vf
p8nH0FMiGDu1al4v+EyzPr2iEcvGGby9wvbZLbfOvrTC2kDitj6KADcoqkPp20fX
8gGZeuPkxZhTDF81VoYmNdVY2V4ygo6adsN+A/Wi+C1Eo8TodimOHvy8XYF4nPzl
Eo0Txjy0PxWP7Yby5gULD/8ntZ4Gl5YNJ3zUIg+kTDdp1Oss3dICyaF5TKsP/ZgX
MEzjpA2RhEAAcTKKdzBuaY60cyGloAq96xoVfQ+ddj7N5ZYIu0I=
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa44PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
// SEQUENCE
//   ObjectIdentifier (2 16 840 1 101 3 4 3 17)
// BITSTRING
// 0046379d375ac5737c5dd8755e408d4527594905a4b4580ba679e7988738d2d67dba1e5b18a685ad3c0a25ecc1d4786fcb2e8dd0fd4cf11b59e0f65195273b4098401169f274f72faed4886fa1ac534b7942155beb4ff93f6876af21f767dac0aa7bedc2d791d213f390df9eec64fddf1f992ce810d4d0b7516283e20c2be2751051c4c890fa405335b7a5fad8c5aa14d40461a75cfd7ee904bce227588cd9f72852e5d0c85d9616d460a68332a0f6fc56fce81c752f6e399bca4ae5996c37823f3a63af0b72bfe0ea1844d1a06c57cc85a035d55583754ec4fe623acc64eb451d572068e16a18bd2ec8fd185ef87a8abc2fcd8d82548988c33194a62343abb75722c6d668fc96cfb9b54250ab50d6b694c8f66e1d94e5775e9d5528bc2aab5fbb8b4a73db04f4899ac8525dda07a03ee423560ccf091af2cd09988f1d816953564d1d32500e37ee9d8169bd936ee80a304c9c608296b6b518f7511e63f41aad9ad6a742960a31f1d003c5de42c5be9d6de540661201a8380723a967818eafe016491db5f034975429b58b6e9e99958d0f1ab3a077c22cf887fe84cb060a0cd96172913d3fecc754ce65c924a149d44ffd2f80bea1849c11630de7eefd578798c8036d8c7034e8b73ec2d50b53c6c55a52ea5f30cb06f6b3e7e458196bb5c1806dcbc2fcfcf075fdd7c486afcbaa41bdcbbff7f8bd27811d627fff1af7a06a500570c1516d6d02c707f7675daf966c355da459c67b46f14784ba4d253ae23d08f138463854e81b6e891b043f488682c2d9f503887c18b746705e9b792c9a2a5a36b0f4327c282365b81b1c757d9e6cc1dcd8e0dad1b90f5e5ece24434d3662bcea73fc949a2bd5fa8fb7f724f0e2a532eff7b9b4b24ae87626f4fea734cb6b7f5623b030d13a8e918af112ce2c91e020d87d88a6207d8873c5241b5851471f7a305163d627fbeee1ffe2f7fd89587c2ec89f784ea40c3e259c2701fc9b3d5bb63da1ee3441be89eb807fb4fc5f56212450654b1fcd501df830a4f71ac4ad2325612eaab8fc5af214c2e12973846d6923c0dc3ba0527bb1ac2d8ad7b587c8558674e7a7fbbe86a763a5a5d08625b158dc49a16d58cc46960bcfa047ce39d9c0730a6230f01df263c00e39b36de52a12b5eca4c46271f2c6177f7c00bcf7a64d6e7ea0d0de026145dcb24c30bac6e4b1e72caff0ab0b37694f16a23d8e55cf709a4b5a96fcde76adb8982f7f317905c808a52894724af3dfe950ea28803e5adee6434a144b529b133b5b5c7e57cf4f34e9b7cd05373ef63ca9de362ad8fa1a3a8f7da18183f6ddae85cb3998423efb813710ac477eb86491661f143b4fd5392c152121016356007a2e60302d2d0881c1a5abfc582894678a1a11107462ed942523a8dffa1362b4d1b9ba64923a387cc92d1b810a18e36a538957719a0f4df95cfd4206fa8b323d203bec241a2bf145616ffec474e0110906fd391e59c91a0a154c8080a232be4a592b55bdae460db475fd81846c7791065baecd7c9b23215663c8a4eedcb98ca7736f18057f074b441c76c06e3e57086d6994c7b26269020ddcbdc542efe8010fe4f777b55fa7c9c7d05322183bb56a5e2ff84cb33ebda211cbc619bcbdc2f6d92db7cebeb4c2da40e2b63e8a003728aa43e9db47d7f201997ae3e4c598530c5f3556862635d558d95e32828e9a76c37e03f5a2f82d44a3c4e876298e1efcbc5d81789cfce5128d13c63cb43f158fed86f2e6050b0fff27b59e0697960d277cd4220fa44c3769d4eb2cddd202c9a1794cab0ffd9817304ce3a40d9184400071328a77306e698eb47321a5a00abdeb1a157d0f9d763ecde59608bb42
// NOLINTEND
constexpr absl::string_view kMlDsa44ExpectedBytesHex =
    R"(
46379d375ac5737c5dd8755e408d4527594905a4b4580ba679e7988738d2d67db
a1e5b18a685ad3c0a25ecc1d4786fcb2e8dd0fd4cf11b59e0f65195273b409840
1169f274f72faed4886fa1ac534b7942155beb4ff93f6876af21f767dac0aa7be
dc2d791d213f390df9eec64fddf1f992ce810d4d0b7516283e20c2be2751051c4
c890fa405335b7a5fad8c5aa14d40461a75cfd7ee904bce227588cd9f72852e5d
0c85d9616d460a68332a0f6fc56fce81c752f6e399bca4ae5996c37823f3a63af
0b72bfe0ea1844d1a06c57cc85a035d55583754ec4fe623acc64eb451d572068e
16a18bd2ec8fd185ef87a8abc2fcd8d82548988c33194a62343abb75722c6d668
fc96cfb9b54250ab50d6b694c8f66e1d94e5775e9d5528bc2aab5fbb8b4a73db0
4f4899ac8525dda07a03ee423560ccf091af2cd09988f1d816953564d1d32500e
37ee9d8169bd936ee80a304c9c608296b6b518f7511e63f41aad9ad6a742960a3
1f1d003c5de42c5be9d6de540661201a8380723a967818eafe016491db5f03497
5429b58b6e9e99958d0f1ab3a077c22cf887fe84cb060a0cd96172913d3fecc75
4ce65c924a149d44ffd2f80bea1849c11630de7eefd578798c8036d8c7034e8b7
3ec2d50b53c6c55a52ea5f30cb06f6b3e7e458196bb5c1806dcbc2fcfcf075fdd
7c486afcbaa41bdcbbff7f8bd27811d627fff1af7a06a500570c1516d6d02c707
f7675daf966c355da459c67b46f14784ba4d253ae23d08f138463854e81b6e891
b043f488682c2d9f503887c18b746705e9b792c9a2a5a36b0f4327c282365b81b
1c757d9e6cc1dcd8e0dad1b90f5e5ece24434d3662bcea73fc949a2bd5fa8fb7f
724f0e2a532eff7b9b4b24ae87626f4fea734cb6b7f5623b030d13a8e918af112
ce2c91e020d87d88a6207d8873c5241b5851471f7a305163d627fbeee1ffe2f7f
d89587c2ec89f784ea40c3e259c2701fc9b3d5bb63da1ee3441be89eb807fb4fc
5f56212450654b1fcd501df830a4f71ac4ad2325612eaab8fc5af214c2e129738
46d6923c0dc3ba0527bb1ac2d8ad7b587c8558674e7a7fbbe86a763a5a5d08625
b158dc49a16d58cc46960bcfa047ce39d9c0730a6230f01df263c00e39b36de52
a12b5eca4c46271f2c6177f7c00bcf7a64d6e7ea0d0de026145dcb24c30bac6e4
b1e72caff0ab0b37694f16a23d8e55cf709a4b5a96fcde76adb8982f7f317905c
808a52894724af3dfe950ea28803e5adee6434a144b529b133b5b5c7e57cf4f34
e9b7cd05373ef63ca9de362ad8fa1a3a8f7da18183f6ddae85cb3998423efb813
710ac477eb86491661f143b4fd5392c152121016356007a2e60302d2d0881c1a5
abfc582894678a1a11107462ed942523a8dffa1362b4d1b9ba64923a387cc92d1
b810a18e36a538957719a0f4df95cfd4206fa8b323d203bec241a2bf145616ffe
c474e0110906fd391e59c91a0a154c8080a232be4a592b55bdae460db475fd818
46c7791065baecd7c9b23215663c8a4eedcb98ca7736f18057f074b441c76c06e
3e57086d6994c7b26269020ddcbdc542efe8010fe4f777b55fa7c9c7d05322183
bb56a5e2ff84cb33ebda211cbc619bcbdc2f6d92db7cebeb4c2da40e2b63e8a00
3728aa43e9db47d7f201997ae3e4c598530c5f3556862635d558d95e32828e9a7
6c37e03f5a2f82d44a3c4e876298e1efcbc5d81789cfce5128d13c63cb43f158f
ed86f2e6050b0fff27b59e0697960d277cd4220fa44c3769d4eb2cddd202c9a17
94cab0ffd9817304ce3a40d9184400071328a77306e698eb47321a5a00abdeb1a
157d0f9d763ecde59608bb42)";

// Obtained via:  openssl genpkey -algorithm ML-DSA-65 \
//                  -provparam ml-dsa.output_formats=seed-only
constexpr absl::string_view kMlDsa65PrivateKeyPem =
    R"(-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMSBCKAIJbTQMlJhPMtf4nn7G0GSMGWPLDHfKEjDwkV
uJXIEXcv
-----END PRIVATE KEY-----
)";

// Extracted from kMlDsa65PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,10000):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier (2 16 840 1 101 3 4 3 18)
//   OCTETSTRING, encapsulates
//     [0] 96d340c94984f32d7f89e7ec6d0648c1963cb0c77ca1230f0915b895c811772f
// NOLINTEND
constexpr absl::string_view kMlDsa65ExpectedSeedBytesHex =
    "96d340c94984f32d7f89e7ec6d0648c1963cb0c77ca1230f0915b895c811772f";

// Obtained via: echo "<kMlDsa65PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kMlDsa65PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
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
LaYEPW5t
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa65PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
//   ObjectIdentifier (2 16 840 1 101 3 4 3 18)
// BITSTRING
// 0028c22b8eb16d429d45afb2a5ea8dc0609ed5475cf9d50c40a8ac0dc4aaf3610855206611364cc6eb064c614ea55e5834167a6ee94d5bc2beee1b820b35286c733a9adba7a62f750d0cb8c1581764543f8e2021b546caa0278055d3bed7d1be5e9ddc29f76b4408c9e64c84645010a20cb77dd4fcec11e708b1f451bb314f2988a46b063ab181515054fcc0c5a1ca96af03e60a3f44b190bd0bb09a099566c7b16cbd2c5c22a8419ee79db39465f0dfd699594b077aa47f06bac5aba84796e143cd35122830efc68734a03a21b7a57c882bf68a1deb8e432326e567a1ba1fad2125065fcb7ce08a7d31b407721b1f3e9e735ebf107364a803fa597659e49975efe7cbe5de9b9bfdb203f36da1e0f4d30af8d9104b9c3d669b47dd280822e87799196772a6a7c2535b32fa477f7ecaf9b3cbe4d8b10028b90d383692b50cf8b8115c2c42074ee20b6a73437de7e07dd57e8267b090d336cafa68607e891069eae4cc8dff66f8f27b627e89d22326536b4c386b0a996fbad15e2d1e8aab1cc5fdf607b259be4fba34b9f9958a2c90b5b088b4d0f8a5d3cc041f1ce5ce37b15444bf25a7ac29bd5ff4bb2b0cfe12c178575ab519f3f922ca1bb9af41de336a77d80ae26e444c47996169f6e9754d5a669e31d9fc98a9943c91607892946349df345c4af4c22a8cc3df985a6a26e63eac2854062881f3e83d17924d5d2f35423a5fb04ea986ab8318827c56e97c48c1b6c5dead0510af5f475e985c49947d45ffa6e9f9bae8b3b2575bfa19208b88439014854b3fb653cd04a2542baf0d8f3152c8032165e566b99ca15547ab75180f8e561cafc3b5b35f9e8fd0f701ef0e50bdb01297d9ba9fc70a9e9fc94e3b9150f4d361a60a6cbc8138b4fe42c3a7f5a0707747d7b3eb2888d4a259e098dda44f083635e3d07e5fc86c3e52f9131e8834a205f939576b4fa91dad5de4275d7a1ce3df7440e9519575bc9f4251b39c1a55be7fc75822e8811e59e4cc7585de2969649a632b6f2141edd535e3d1d460057d38f1221205d7a2f8d71e75213c9b0301f7d24fde1ed2ba898a22a6c8779fd720429c9fe3b15de0dd21446bf3d8858bc2cb572891b6a8c5838e4abfff8afaf9caa0e8aed6b3d635462801c2f7845c40dbe61d0f8887a4a4c548729fb0f599a2403cc1ec9d285f7371e2619292a205e7d58be243ab89cdc6c74e7de951788fcac4c44181944f015e11a4b9a675d5626aa7f00dcc5285e75c069d3b1b32ae5a08f0197b30a9cf3e9e88eecee3b2019ab8be096b4ed8310bf0f4837f644d0235d902c28f9d2bb11bc7f5d0477d81ed1a5df79066a2fd8e944d662e3678267fa0370d028baff8a509ca7dcf3432264ef8695c2ebaf3fb2a14342675eb07811c74ff9bdf8bc9bd0241cb97e5ba5ee1192538acf49b4b2b49436af5ccfdf710c1b177ff0895f3484b70c1ac174760dc68a7d9a64776330bf7d27b7545e222e1da6b42a6065af593c8abb078cd6ea3df625f1af52a59504298c50ba5ee1c4e752e7b5dbd2a58f2b0589d937e5297b929bd5119e2b66cfcdeca1f10a73f54eee10583ee8d9c00262e184a84d61419d1a6213ebfaf2a4fbc1607f0d374dc69af8264ea1942cee26d7e8d2bb6d808d52256f3b920d43368e54aaa26b51da4e0a7426df83b72895e632ddf7fe593bb95084dd033f2762130f23b457768b9d85bf26c737faddbf65f452f4d9aaa5daaaa77e372eaea90206af5f7ccd4490333e55d13784534a56cdd32f28f23c0879a6c8d7ede9915e82ea0396da2918da6510d0e7bddd5718153808740233afcaa3703196789cf3fb74fd396bd55c3b57220c8e8b6d0cac2d0b2098286d5addca52c1de8556c8ee9f0e6ebd140f930fe467c41eb93fe5f4bc931d154cb7153d49b7ac2648c3c32008bdc3c7d92dd1c9d13e5b484a25420778c7f459dcff8acc1a4c1bc22bcb50cafe8678d6b163f85361134b35c878b70a336a72d7ffafac4e159d7c377cbd1f645f3cd20ab47dac91556a007cebf42c683a159c92f278db6b06801710a88baabf6e1f1641183f36f2e7a6b610aef063d50523f12e2b904167189b150da40f1f5f0f642a74bba693575caf34e9f411d41a1ea385229a1b6ba084de1d8184a0c69720ea0de94238456f4738e448b71731deb9d539e2abdad7091bf08881d6696bcfeb95825787d701db16a6f4c0733665b53e4d54382c7baa52067bd486e7a80797a10caebdfff932e1cdfa94739356c1476d12612132cf5ab2de2e50bf6b942084fc2d1306c149007e35fce99fd18767ffb21d71dee75815fec9ee69c4c7080e4726bcb5aaac2d7dcc292fd80b99b2a508bede297ad1021ca3c50b9d4105f5a58703e43f94e91c0d283797fddc489181050f4c39b592297a628ffa8c092691b9adb63855303174e2aae07ec984cb31d6871ecbc1cef469cb314e8eb7088d0591eaac778768749a3cca29455320aa55e73231ad00be7a21c11fe02b12b6fa686f248c923d800d738abef72dbe6d158b84c870c4cfc25859d1ad0bce7ca71d502a0741c9ab897eced99ce4a9f33da6ad5bbf9c35ca25f235653e931914eb801fecfef50c1a70308875e604e36f6467327b9e95dd4783d8b567e72a7eb71d0d50724b1de3bb241eb380dbc3c56f1282eee837c8662eaf6deee6bbac681f6b0df6be133da068bb2c05c73120c9e35bcfdeac2f22e4b01c66566c73dedf4cb5d8234aa6a0d2caa3c1a56affd73d510d155432da6043d6e6d
// NOLINTEND
constexpr absl::string_view kMlDsa65ExpectedBytesHex =
    R"(
28c22b8eb16d429d45afb2a5ea8dc0609ed5475cf9d50c40a8ac0dc4aaf361085
5206611364cc6eb064c614ea55e5834167a6ee94d5bc2beee1b820b35286c733a
9adba7a62f750d0cb8c1581764543f8e2021b546caa0278055d3bed7d1be5e9dd
c29f76b4408c9e64c84645010a20cb77dd4fcec11e708b1f451bb314f2988a46b
063ab181515054fcc0c5a1ca96af03e60a3f44b190bd0bb09a099566c7b16cbd2
c5c22a8419ee79db39465f0dfd699594b077aa47f06bac5aba84796e143cd3512
2830efc68734a03a21b7a57c882bf68a1deb8e432326e567a1ba1fad2125065fc
b7ce08a7d31b407721b1f3e9e735ebf107364a803fa597659e49975efe7cbe5de
9b9bfdb203f36da1e0f4d30af8d9104b9c3d669b47dd280822e87799196772a6a
7c2535b32fa477f7ecaf9b3cbe4d8b10028b90d383692b50cf8b8115c2c42074e
e20b6a73437de7e07dd57e8267b090d336cafa68607e891069eae4cc8dff66f8f
27b627e89d22326536b4c386b0a996fbad15e2d1e8aab1cc5fdf607b259be4fba
34b9f9958a2c90b5b088b4d0f8a5d3cc041f1ce5ce37b15444bf25a7ac29bd5ff
4bb2b0cfe12c178575ab519f3f922ca1bb9af41de336a77d80ae26e444c479961
69f6e9754d5a669e31d9fc98a9943c91607892946349df345c4af4c22a8cc3df9
85a6a26e63eac2854062881f3e83d17924d5d2f35423a5fb04ea986ab8318827c
56e97c48c1b6c5dead0510af5f475e985c49947d45ffa6e9f9bae8b3b2575bfa1
9208b88439014854b3fb653cd04a2542baf0d8f3152c8032165e566b99ca15547
ab75180f8e561cafc3b5b35f9e8fd0f701ef0e50bdb01297d9ba9fc70a9e9fc94
e3b9150f4d361a60a6cbc8138b4fe42c3a7f5a0707747d7b3eb2888d4a259e098
dda44f083635e3d07e5fc86c3e52f9131e8834a205f939576b4fa91dad5de4275
d7a1ce3df7440e9519575bc9f4251b39c1a55be7fc75822e8811e59e4cc7585de
2969649a632b6f2141edd535e3d1d460057d38f1221205d7a2f8d71e75213c9b0
301f7d24fde1ed2ba898a22a6c8779fd720429c9fe3b15de0dd21446bf3d8858b
c2cb572891b6a8c5838e4abfff8afaf9caa0e8aed6b3d635462801c2f7845c40d
be61d0f8887a4a4c548729fb0f599a2403cc1ec9d285f7371e2619292a205e7d5
8be243ab89cdc6c74e7de951788fcac4c44181944f015e11a4b9a675d5626aa7f
00dcc5285e75c069d3b1b32ae5a08f0197b30a9cf3e9e88eecee3b2019ab8be09
6b4ed8310bf0f4837f644d0235d902c28f9d2bb11bc7f5d0477d81ed1a5df7906
6a2fd8e944d662e3678267fa0370d028baff8a509ca7dcf3432264ef8695c2eba
f3fb2a14342675eb07811c74ff9bdf8bc9bd0241cb97e5ba5ee1192538acf49b4
b2b49436af5ccfdf710c1b177ff0895f3484b70c1ac174760dc68a7d9a6477633
0bf7d27b7545e222e1da6b42a6065af593c8abb078cd6ea3df625f1af52a59504
298c50ba5ee1c4e752e7b5dbd2a58f2b0589d937e5297b929bd5119e2b66cfcde
ca1f10a73f54eee10583ee8d9c00262e184a84d61419d1a6213ebfaf2a4fbc160
7f0d374dc69af8264ea1942cee26d7e8d2bb6d808d52256f3b920d43368e54aaa
26b51da4e0a7426df83b72895e632ddf7fe593bb95084dd033f2762130f23b457
768b9d85bf26c737faddbf65f452f4d9aaa5daaaa77e372eaea90206af5f7ccd4
490333e55d13784534a56cdd32f28f23c0879a6c8d7ede9915e82ea0396da2918
da6510d0e7bddd5718153808740233afcaa3703196789cf3fb74fd396bd55c3b5
7220c8e8b6d0cac2d0b2098286d5addca52c1de8556c8ee9f0e6ebd140f930fe4
67c41eb93fe5f4bc931d154cb7153d49b7ac2648c3c32008bdc3c7d92dd1c9d13
e5b484a25420778c7f459dcff8acc1a4c1bc22bcb50cafe8678d6b163f8536113
4b35c878b70a336a72d7ffafac4e159d7c377cbd1f645f3cd20ab47dac91556a0
07cebf42c683a159c92f278db6b06801710a88baabf6e1f1641183f36f2e7a6b6
10aef063d50523f12e2b904167189b150da40f1f5f0f642a74bba693575caf34e
9f411d41a1ea385229a1b6ba084de1d8184a0c69720ea0de94238456f4738e448
b71731deb9d539e2abdad7091bf08881d6696bcfeb95825787d701db16a6f4c07
33665b53e4d54382c7baa52067bd486e7a80797a10caebdfff932e1cdfa947393
56c1476d12612132cf5ab2de2e50bf6b942084fc2d1306c149007e35fce99fd18
767ffb21d71dee75815fec9ee69c4c7080e4726bcb5aaac2d7dcc292fd80b99b2
a508bede297ad1021ca3c50b9d4105f5a58703e43f94e91c0d283797fddc48918
1050f4c39b592297a628ffa8c092691b9adb63855303174e2aae07ec984cb31d6
871ecbc1cef469cb314e8eb7088d0591eaac778768749a3cca29455320aa55e73
231ad00be7a21c11fe02b12b6fa686f248c923d800d738abef72dbe6d158b84c8
70c4cfc25859d1ad0bce7ca71d502a0741c9ab897eced99ce4a9f33da6ad5bbf9
c35ca25f235653e931914eb801fecfef50c1a70308875e604e36f6467327b9e95
dd4783d8b567e72a7eb71d0d50724b1de3bb241eb380dbc3c56f1282eee837c86
62eaf6deee6bbac681f6b0df6be133da068bb2c05c73120c9e35bcfdeac2f22e4
b01c66566c73dedf4cb5d8234aa6a0d2caa3c1a56affd73d510d155432da6043d
6e6d
)";

// Obtained via:  openssl genpkey -algorithm ML-DSA-87 \
//                  -provparam ml-dsa.output_formats=seed-only
constexpr absl::string_view kMlDsa87PrivateKeyPem = R"(
-----BEGIN PRIVATE KEY-----
MDQCAQAwCwYJYIZIAWUDBAMTBCKAIKiDlMxCX5hiEpwKZ+pQd9IcoGdLJtzX+1dx
BDhzE6Av
-----END PRIVATE KEY-----
)";

// Extracted from kMlDsa87PrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,10000):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier (2 16 840 1 101 3 4 3 19)
//   OCTETSTRING, encapsulates
//     [0] a88394cc425f9862129c0a67ea5077d21ca0674b26dcd7fb577104387313a02f
// NOLINTEND
constexpr absl::string_view kMlDsa87ExpectedSeedBytesHex =
    "a88394cc425f9862129c0a67ea5077d21ca0674b26dcd7fb577104387313a02f";

// Obtained via: echo "<kMlDsa87PrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kMlDsa87PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
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
yV1N6EjHQL5rajvN/3g7X8Y0NfJQ6g==
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa87PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
//   SEQUENCE
//     ObjectIdentifier (2 16 840 1 101 3 4 3 19)
//   BITSTRING
//   0089e7bd8c8f8f7462bdb9b626694dba6da9da6aa6e0cac21be5a34c042366a90e87b5a288d7ee07431e7cb4d4b0f591a094eeda168ce4a02940d2aa7f8ca98c6c8f80572e49788ec112bd8d48aeb871fdedb7e8345cafc000d6df0914729b6a69fecc55c47fb7cc1b07f6738bc28ef431e3b6e0810b338a7983c193904a3e67e1f1bf7eb0261740e9d463a080e6ca116005030bc27b0cb9b4f422452816a7bab7d80718db800c971bd6781757e3c51d36dba0b5bc32fcc4b5d832ef6bcc1eb9097a8fefa5919e137a33c29b2f1275f5db5b688730f52a58ce627cec99c5ae510c56bbe1628f2bfa5c0ce60220a60a62d36e4633a32d001a94e92876779e548d671df3cd52b0ba068650c871395435e6edaffffa8fc003e7a98db6c854aa8580fe5e587156f5ca694e3fb8cbbfce4dd912b95dcf43808dc18d3c14a6a2ed0103d34086b5d44c29465761bc017c48178f09483fce73a49d4fdaa4bc86e1bc84a080edbab440c99ce6b25700ee019d7500f4a97e243442e3feb035480783b14b1cad0a81ff6add818179eb8adff07da7aac84c1aafef13761f932600990a2bd342eb626a7222ef256ae5244ed99d48bdac0c401fa753a749e460c238a101c4d3e0ee96077c8e8a97304ea8f65b93ccfe798b19da2c29910843520ab405b69320ecd4c67c1f525dd4a3a6d9275fbe06430d96ad15fa4198d9b92ac279ced841f3742767559cce846f3660077d441869e06090a320b60328895bda09d81a692a56b149d5d91ecc348a4c0bb6b26f349b105dd82ba76f687191c8647dca7d95697e8da7dd7a6e6d18ef4822d5538ffbed89e74913c1fc82aa01c6f51d4573114d04f3abc1970e24013669cc94172f072658a1a27ee373d32290a209a2e888f6514fb1c17d1aa2e4082668c46b3dfa2110d50fd4e97fc8f9d2a6ea74e28f3251a1f29cbfa817a675d4d3303ca2175e407542f9229a6f0cd9e6218bfcc29a396c9048a4eb722fb12d62186339a5ba560e4091003a2ee859ee5e655bceaed034e1e28392a68fec094166e6d63191e9263b28c816bc7970379149953d9088106fb7a8501ae2623b890dbf5fcf27894b21348897b1c06fa521e536d07a0b8513ec027ec8226d572a0a21737cb03f8d82de86e85cbfff7a4960047786deba31054d69a75d683a60d71d74d28988e750556acab3bea3595a0c5bf45bf6bb2bf48ffa56d40d758b894811d0328dfdd4a67b8d2e5e5e60a3b2c223cad7fe73002d5e6ccf417860c19b07f1d6c2ae381ac3ed98d0ab69ee604f625da6190957451d9a0d7d8393f5fcf48e075557d81cf5896f30cc96d34bc0332b5d16ce55edecdc39fd97d28e75a80f81c7ba10862d66487b07d4a52720bdbd9499f043240858d6ef9b09490a833030217dca929aac8b70693da90ea187d64d39d6a643be180718f17a82038880788da85e43111ea787c14bfe2610b4f312672876ba288bb39fdfba8d467d08635f8381608dea1e78b5cfc7983ecdb020ca93b4cee266cf3672b54acb5601d4913f680c63e5a0b2c5fee1cae9493ae8d234ffad7bd7420f8198e07a88b7a1a7aa3ee388d531b2a231170d501b8b639daf022531e98835257e43fd98c124a370a78faa4c01b4aab3d93b64a998099fd44bb5ee8947505703390722a97f8658ea65ccd7a5356d3b1735ed7d32bc4b658612ea5147ea7d04e278ad8735ad9d5f6d3f4a896ede262ea9baf2985fee3e5227f2ba7fcb913b272d3540c115a1c455ced909a6e76698041107f0b86ad8b26f2dfd8f64206560b987075576d97be2e561f65fe73d525d49e657e5b9ac4b434156692d957a8521e42c8dc32a1f7c62d5d88927c8c79b57ea445f89fb20641f197a9ac110101e1bca6ef0a7a2c1eee250fcfeee2f9a9e0e0ab0d30c465b0e7e84f0df0e92f56abf0296c12a6090c905630d205fd820b066650990b3a754aadac8bf659cd4dd5564ffb8448362f09fcb2518fe03227d4ad8044c3171e788e48e7d7d62fc2406fdcd4b24d4b604e0c88686ff697a3c85c4059ac399fbf5f3c8dedc15b8ba009ce09b4fbc3ce5a2bc7234b1bcfa0b662ccec47531f5b6dbfc33e0e3460608f2ea41441f4647e0d8a463db86f18183a46d8f652d8058c6579753be2d414e22262e8eb60d0c0deb94914fbcbec2acf70f2427688995d792d7429e48daa3adb2dde74d751a33c120118292c484c32b65d1980773ab6ce1d61e5835ba6a3606d40390a8b4e9197972c2a10b8b75b73c3265a1d89b1c2f8eaf722b83553afb9afd2708ac15365e8286a2044ec14ebf10f74613618c122a60e8a2151b04131e8a2d86233b1ebbb49ef7f1a8d8962d91549e3fd6ca207f56cddacb0596a90fd2e66277eab015e231040bd041307f6ea750bf1d4370c30f52c602c2a02e0b8ea946ae82d19ab72b4be240a0341ba16647ea87fa91207861543e6030849e450c3942d8d1ef99d658ca048fbd90fafac3bd16034c6c01e608629b948a25f1a0accc635b8cef44995579d7514fba119c283193359d368a2d716b5e25a2bc09c85d900183e7f2fbe3c8e1f6cd3994b3b3ea1af3e2848612cccbedeb56d0fa809fbe3a805631b444e6a3b0d9ab4e56c6b19490ca9f7ad1f62bed656dd77c1ee55020b22957a2408f75d54ffa0b1b66248e641d3f39f62b63e60c335720141cb8e912ca0deea652dc60893620d9d556753fee2cb81435e6080e0a5af9841a434e8112d889156909e9545671388ee220721459475d2e59ce3336a808e0dcee8e965823a6a01087d7356b5f93c2c6ad11b1405ba9a5de693de9e6be510d23b848ce1a142083141d68e3768195ebf9f28e9f2dcd0200d78b98013467a907f589aae091b580a290ab94f42e17d33594fcbd6946c178864906c79b22794f12f7e1a631483882efadc0043352b2bc1a83462f79360761251e2d98a65fe0fe9ad44bdef688275c41c2660467ab5c178435712fb8aadd64828e2ceda0a2b6b98d1ba2d5daf42daba95abb4553998be59e63bce3a32c2c4057fc095083e5a75f9896e6a73c31b0766a8974dc1a4dab58323e798b5ec64914e51c3682198f43172736f5417931fc82e94554aa0f2805221976cf83c585f1c493fe6b401f6d2c01c81c136e3c7045a7a39e98200dd74b2aa4908c783d2703c295c8949e9c41b07dc7cb2310ac2c97f40bc66a9b1746e649704687be21ff488a298e75f3fb822ca70f7c38371ae2761312d722ef72e35474f91a048cacfc319d956dc79e98b44d3e2249d92c7417149849d161e7bce424d1f4c6671bfba298ed822687fd29ff52a0af41b350acc0dc62c7a58aaba63f1b835edb123e2ce950aa1e950c0f44f88fa059adce1ac365c75058809769dbdd96410c00bddf052a585721447a487d58ab59702c0fe16d266273af494a5db8c455d1e3195d71e57989ae1483d4b963446226a86e6d03ab8074b208cc6cb9aae629be129d949a7941293226f168fd6aee618f2bc9368670a9b6b8108b4c27c5ed0ee43e7ee2a1490e09dfe1b9e53fdd33a5997362c8496ab2f4f3c6f0e821e40a6b310a68477248487c742a2e6cd4bc5ac2a068d92bc35f3426de30bd6830b36a3195210f325b1e692ae82c60f817a5bcf960d440cb51c95d4de848c740be6b6a3bcdff783b5fc63435f250ea
// NOLINTEND
constexpr absl::string_view kMlDsa87ExpectedBytesHex =
    R"(
89e7bd8c8f8f7462bdb9b626694dba6da9da6aa6e0cac21be5a34c042366a90e8
7b5a288d7ee07431e7cb4d4b0f591a094eeda168ce4a02940d2aa7f8ca98c6c8f
80572e49788ec112bd8d48aeb871fdedb7e8345cafc000d6df0914729b6a69fec
c55c47fb7cc1b07f6738bc28ef431e3b6e0810b338a7983c193904a3e67e1f1bf
7eb0261740e9d463a080e6ca116005030bc27b0cb9b4f422452816a7bab7d8071
8db800c971bd6781757e3c51d36dba0b5bc32fcc4b5d832ef6bcc1eb9097a8fef
a5919e137a33c29b2f1275f5db5b688730f52a58ce627cec99c5ae510c56bbe16
28f2bfa5c0ce60220a60a62d36e4633a32d001a94e92876779e548d671df3cd52
b0ba068650c871395435e6edaffffa8fc003e7a98db6c854aa8580fe5e587156f
5ca694e3fb8cbbfce4dd912b95dcf43808dc18d3c14a6a2ed0103d34086b5d44c
29465761bc017c48178f09483fce73a49d4fdaa4bc86e1bc84a080edbab440c99
ce6b25700ee019d7500f4a97e243442e3feb035480783b14b1cad0a81ff6add81
8179eb8adff07da7aac84c1aafef13761f932600990a2bd342eb626a7222ef256
ae5244ed99d48bdac0c401fa753a749e460c238a101c4d3e0ee96077c8e8a9730
4ea8f65b93ccfe798b19da2c29910843520ab405b69320ecd4c67c1f525dd4a3a
6d9275fbe06430d96ad15fa4198d9b92ac279ced841f3742767559cce846f3660
077d441869e06090a320b60328895bda09d81a692a56b149d5d91ecc348a4c0bb
6b26f349b105dd82ba76f687191c8647dca7d95697e8da7dd7a6e6d18ef4822d5
538ffbed89e74913c1fc82aa01c6f51d4573114d04f3abc1970e24013669cc941
72f072658a1a27ee373d32290a209a2e888f6514fb1c17d1aa2e4082668c46b3d
fa2110d50fd4e97fc8f9d2a6ea74e28f3251a1f29cbfa817a675d4d3303ca2175
e407542f9229a6f0cd9e6218bfcc29a396c9048a4eb722fb12d62186339a5ba56
0e4091003a2ee859ee5e655bceaed034e1e28392a68fec094166e6d63191e9263
b28c816bc7970379149953d9088106fb7a8501ae2623b890dbf5fcf27894b2134
8897b1c06fa521e536d07a0b8513ec027ec8226d572a0a21737cb03f8d82de86e
85cbfff7a4960047786deba31054d69a75d683a60d71d74d28988e750556acab3
bea3595a0c5bf45bf6bb2bf48ffa56d40d758b894811d0328dfdd4a67b8d2e5e5
e60a3b2c223cad7fe73002d5e6ccf417860c19b07f1d6c2ae381ac3ed98d0ab69
ee604f625da6190957451d9a0d7d8393f5fcf48e075557d81cf5896f30cc96d34
bc0332b5d16ce55edecdc39fd97d28e75a80f81c7ba10862d66487b07d4a52720
bdbd9499f043240858d6ef9b09490a833030217dca929aac8b70693da90ea187d
64d39d6a643be180718f17a82038880788da85e43111ea787c14bfe2610b4f312
672876ba288bb39fdfba8d467d08635f8381608dea1e78b5cfc7983ecdb020ca9
3b4cee266cf3672b54acb5601d4913f680c63e5a0b2c5fee1cae9493ae8d234ff
ad7bd7420f8198e07a88b7a1a7aa3ee388d531b2a231170d501b8b639daf02253
1e98835257e43fd98c124a370a78faa4c01b4aab3d93b64a998099fd44bb5ee89
47505703390722a97f8658ea65ccd7a5356d3b1735ed7d32bc4b658612ea5147e
a7d04e278ad8735ad9d5f6d3f4a896ede262ea9baf2985fee3e5227f2ba7fcb91
3b272d3540c115a1c455ced909a6e76698041107f0b86ad8b26f2dfd8f6420656
0b987075576d97be2e561f65fe73d525d49e657e5b9ac4b434156692d957a8521
e42c8dc32a1f7c62d5d88927c8c79b57ea445f89fb20641f197a9ac110101e1bc
a6ef0a7a2c1eee250fcfeee2f9a9e0e0ab0d30c465b0e7e84f0df0e92f56abf02
96c12a6090c905630d205fd820b066650990b3a754aadac8bf659cd4dd5564ffb
8448362f09fcb2518fe03227d4ad8044c3171e788e48e7d7d62fc2406fdcd4b24
d4b604e0c88686ff697a3c85c4059ac399fbf5f3c8dedc15b8ba009ce09b4fbc3
ce5a2bc7234b1bcfa0b662ccec47531f5b6dbfc33e0e3460608f2ea41441f4647
e0d8a463db86f18183a46d8f652d8058c6579753be2d414e22262e8eb60d0c0de
b94914fbcbec2acf70f2427688995d792d7429e48daa3adb2dde74d751a33c120
118292c484c32b65d1980773ab6ce1d61e5835ba6a3606d40390a8b4e9197972c
2a10b8b75b73c3265a1d89b1c2f8eaf722b83553afb9afd2708ac15365e8286a2
044ec14ebf10f74613618c122a60e8a2151b04131e8a2d86233b1ebbb49ef7f1a
8d8962d91549e3fd6ca207f56cddacb0596a90fd2e66277eab015e231040bd041
307f6ea750bf1d4370c30f52c602c2a02e0b8ea946ae82d19ab72b4be240a0341
ba16647ea87fa91207861543e6030849e450c3942d8d1ef99d658ca048fbd90fa
fac3bd16034c6c01e608629b948a25f1a0accc635b8cef44995579d7514fba119
c283193359d368a2d716b5e25a2bc09c85d900183e7f2fbe3c8e1f6cd3994b3b3
ea1af3e2848612cccbedeb56d0fa809fbe3a805631b444e6a3b0d9ab4e56c6b19
490ca9f7ad1f62bed656dd77c1ee55020b22957a2408f75d54ffa0b1b66248e64
1d3f39f62b63e60c335720141cb8e912ca0deea652dc60893620d9d556753fee2
cb81435e6080e0a5af9841a434e8112d889156909e9545671388ee22072145947
5d2e59ce3336a808e0dcee8e965823a6a01087d7356b5f93c2c6ad11b1405ba9a
5de693de9e6be510d23b848ce1a142083141d68e3768195ebf9f28e9f2dcd0200
d78b98013467a907f589aae091b580a290ab94f42e17d33594fcbd6946c178864
906c79b22794f12f7e1a631483882efadc0043352b2bc1a83462f79360761251e
2d98a65fe0fe9ad44bdef688275c41c2660467ab5c178435712fb8aadd64828e2
ceda0a2b6b98d1ba2d5daf42daba95abb4553998be59e63bce3a32c2c4057fc09
5083e5a75f9896e6a73c31b0766a8974dc1a4dab58323e798b5ec64914e51c368
2198f43172736f5417931fc82e94554aa0f2805221976cf83c585f1c493fe6b40
1f6d2c01c81c136e3c7045a7a39e98200dd74b2aa4908c783d2703c295c8949e9
c41b07dc7cb2310ac2c97f40bc66a9b1746e649704687be21ff488a298e75f3fb
822ca70f7c38371ae2761312d722ef72e35474f91a048cacfc319d956dc79e98b
44d3e2249d92c7417149849d161e7bce424d1f4c6671bfba298ed822687fd29ff
52a0af41b350acc0dc62c7a58aaba63f1b835edb123e2ce950aa1e950c0f44f88
fa059adce1ac365c75058809769dbdd96410c00bddf052a585721447a487d58ab
59702c0fe16d266273af494a5db8c455d1e3195d71e57989ae1483d4b96344622
6a86e6d03ab8074b208cc6cb9aae629be129d949a7941293226f168fd6aee618f
2bc9368670a9b6b8108b4c27c5ed0ee43e7ee2a1490e09dfe1b9e53fdd33a5997
362c8496ab2f4f3c6f0e821e40a6b310a68477248487c742a2e6cd4bc5ac2a068
d92bc35f3426de30bd6830b36a3195210f325b1e692ae82c60f817a5bcf960d44
0cb51c95d4de848c740be6b6a3bcdff783b5fc63435f250ea
)";

struct MlDsaPublicKeyTestParams {
  std::string test_name;
  MlDsaParameters parameters;
  absl::string_view expected_bytes_hex;
  absl::string_view public_key_pem;
};

using PemParserMlDsaPublicKeyTestVectorsTest =
    testing::TestWithParam<MlDsaPublicKeyTestParams>;

MlDsaPublicKey CreateMlDsaPublicKeyFromTestVector(
    const MlDsaPublicKeyTestParams& params) {
  std::string clean_hex(params.expected_bytes_hex);
  clean_hex.erase(
      std::remove_if(clean_hex.begin(), clean_hex.end(),
                     [](unsigned char c) { return std::isspace(c); }),
      clean_hex.end());
  std::string pub_bytes;
  ABSL_CHECK(absl::HexStringToBytes(clean_hex, &pub_bytes));
  absl::StatusOr<MlDsaPublicKey> public_key = MlDsaPublicKey::Create(
      params.parameters, pub_bytes,
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);
  return *public_key;
}

TEST_P(PemParserMlDsaPublicKeyTestVectorsTest, PemToSignaturePublicKey) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  MlDsaPublicKeyTestParams params = GetParam();
  MlDsaPublicKey public_key = CreateMlDsaPublicKeyFromTestVector(params);

  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaPublicKey, parsed_public_key,
      PemToMlDsaPublicKey(params.public_key_pem, params.parameters,
                          GetPartialKeyAccess()));
  EXPECT_EQ(parsed_public_key, public_key);
}

TEST(PemParserMlDsaPublicKeyTest,
     PemToSignaturePublicKeyMlDsaFailsForNonNoPrefixVariant) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kTink));

  EXPECT_THAT(
      PemToMlDsaPublicKey(kMlDsa65PublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPublicKeyTest,
     PemToSignaturePublicKeyMlDsaFailsForPrivateKeyPem) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(
      PemToMlDsaPublicKey(kP256PrivateKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(
      PemToMlDsaPublicKey(kMlDsa65PrivateKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPublicKeyTest,
     PemToSignaturePublicKeyMlDsaFailsForInvalidPem) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(
      PemToMlDsaPublicKey(
          "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
          params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPublicKeyTest,
     PemToSignaturePublicKeyMlDsaFailsForNonMlDsaKey) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(
      PemToMlDsaPublicKey(kP256PublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPublicKeyTest,
     PemToSignaturePublicKeyMlDsaFailsForMismatchedInstance) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa44_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa44,
                              MlDsaParameters::Variant::kNoPrefix));
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa65_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa87_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToMlDsaPublicKey(kMlDsa44PublicKeyPem, mldsa65_params,
                                  GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPublicKey(kMlDsa65PublicKeyPem, mldsa87_params,
                                  GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPublicKey(kMlDsa87PublicKeyPem, mldsa44_params,
                                  GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

std::vector<MlDsaPublicKeyTestParams> GetMlDsaPublicKeyTestParams() {
  absl::StatusOr<MlDsaParameters> mldsa44_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa44, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa44_params);
  absl::StatusOr<MlDsaParameters> mldsa65_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa65_params);
  absl::StatusOr<MlDsaParameters> mldsa87_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa87_params);
  return {
      MlDsaPublicKeyTestParams{
          /*test_name=*/"ML_DSA_44",
          /*parameters=*/*mldsa44_params,
          /*expected_bytes_hex=*/kMlDsa44ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa44PublicKeyPem,
      },
      MlDsaPublicKeyTestParams{
          /*test_name=*/"ML_DSA_65",
          /*parameters=*/*mldsa65_params,
          /*expected_bytes_hex=*/kMlDsa65ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa65PublicKeyPem,
      },
      MlDsaPublicKeyTestParams{
          /*test_name=*/"ML_DSA_87",
          /*parameters=*/*mldsa87_params,
          /*expected_bytes_hex=*/kMlDsa87ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa87PublicKeyPem,
      },
  };
}

INSTANTIATE_TEST_SUITE_P(
    PemParserMlDsaPublicKeyTest, PemParserMlDsaPublicKeyTestVectorsTest,
    testing::ValuesIn(GetMlDsaPublicKeyTestParams()),
    [](const testing::TestParamInfo<MlDsaPublicKeyTestParams>& info) {
      return info.param.test_name;
    });

struct MlDsaPrivateKeyTestParams {
  std::string test_name;
  MlDsaParameters parameters;
  absl::string_view expected_seed_bytes_hex;
  absl::string_view private_key_pem;
  absl::string_view public_key_pem;
};

using MlDsaPrivateKeyTestVectorsTest =
    testing::TestWithParam<MlDsaPrivateKeyTestParams>;

TEST_P(MlDsaPrivateKeyTestVectorsTest, PemToSignaturePrivateKey) {
  MlDsaPrivateKeyTestParams params = GetParam();
  if (IsBoringSsl()) {
    TINK_ASSERT_OK_AND_ASSIGN(
        MlDsaPrivateKey, expected_private_key,
        MlDsaPrivateKey::Create(
            params.parameters,
            RestrictedData(HexDecodeOrDie(params.expected_seed_bytes_hex),
                           InsecureSecretKeyAccess::Get()),
            /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
    TINK_ASSERT_OK_AND_ASSIGN(
        MlDsaPrivateKey, private_key,
        PemToMlDsaPrivateKey(params.private_key_pem, params.parameters,
                             InsecureSecretKeyAccess::Get(),
                             GetPartialKeyAccess()));
    EXPECT_EQ(private_key, expected_private_key);
  } else {
    EXPECT_THAT(PemToMlDsaPrivateKey(params.private_key_pem, params.parameters,
                                     InsecureSecretKeyAccess::Get(),
                                     GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  }
}

TEST_P(MlDsaPrivateKeyTestVectorsTest, SignAndVerify) {
  if (!IsBoringSsl()) {
    GTEST_SKIP() << "ML-DSA is only supported with BoringSSL.";
  }
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  MlDsaPrivateKeyTestParams params = GetParam();

  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaPrivateKey, private_key,
      PemToMlDsaPrivateKey(params.private_key_pem, params.parameters,
                           InsecureSecretKeyAccess::Get(),
                           GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, private_handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              private_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      private_handle.GetPrimitive<PublicKeySign>(Config2026()));

  constexpr absl::string_view kMessage = "test message";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  // Verify using the public key obtained from the private key.
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle_from_priv,
      private_handle.GetPublicKeysetHandle(KeyGenConfig2026()));
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>,
                            verifier_from_priv,
                            pub_handle_from_priv->GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_priv->Verify(signature, kMessage), IsOk());

  // Verify using the public key obtained from PEM.
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaPublicKey, public_key_from_pem,
      PemToMlDsaPublicKey(params.public_key_pem, params.parameters,
                          GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, pub_handle_from_pem,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              public_key_from_pem, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>, verifier_from_pem,
                            pub_handle_from_pem.GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_pem->Verify(signature, kMessage), IsOk());
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForNonNoPrefixVariant) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kTink));

  EXPECT_THAT(PemToMlDsaPrivateKey(kMlDsa65PrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForPublicKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToMlDsaPrivateKey(kMlDsa65PublicKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPrivateKey(kP256PublicKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(
      PemToMlDsaPrivateKey(
          "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
          params, InsecureSecretKeyAccess::Get(), GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForNonMlDsaKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToMlDsaPrivateKey(kP256PrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPrivateKey(kP256Pkcs8PrivateKeyPem, params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForMismatchedInstance) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa44_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa44,
                              MlDsaParameters::Variant::kNoPrefix));
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa65_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa87_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa87,
                              MlDsaParameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToMlDsaPrivateKey(kMlDsa44PrivateKeyPem, mldsa65_params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPrivateKey(kMlDsa65PrivateKeyPem, mldsa87_params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(PemToMlDsaPrivateKey(kMlDsa87PrivateKeyPem, mldsa44_params,
                                   InsecureSecretKeyAccess::Get(),
                                   GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserMlDsaPrivateKeyTest,
     PemToSignaturePrivateKeyMlDsaFailsForBareSeedFormat) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, mldsa44_params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa44,
                              MlDsaParameters::Variant::kNoPrefix));

  // Obtained via: openssl genpkey -algorithm ML-DSA-44 \
  //                 -provparam ml-dsa.output_formats=bare-seed
  constexpr absl::string_view kMlDsa44BareSeedPrivateKeyPem =
      R"(-----BEGIN PRIVATE KEY-----
MDICAQAwCwYJYIZIAWUDBAMRBCBJWM7V429s7W7c7nS9m1G/vA2eK9qM8tC2/xI9
nA47tA==
-----END PRIVATE KEY-----)";

  EXPECT_THAT(PemToMlDsaPrivateKey(
                  kMlDsa44BareSeedPrivateKeyPem, mldsa44_params,
                  InsecureSecretKeyAccess::Get(), GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

std::vector<MlDsaPrivateKeyTestParams> GetMlDsaPrivateKeyTestParams() {
  absl::StatusOr<MlDsaParameters> mldsa44_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa44, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa44_params);
  absl::StatusOr<MlDsaParameters> mldsa65_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa65, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa65_params);
  absl::StatusOr<MlDsaParameters> mldsa87_params = MlDsaParameters::Create(
      MlDsaParameters::Instance::kMlDsa87, MlDsaParameters::Variant::kNoPrefix);
  ABSL_CHECK_OK(mldsa87_params);
  return {
      MlDsaPrivateKeyTestParams{
          /*test_name=*/"ML_DSA_44",
          /*parameters=*/*mldsa44_params,
          /*expected_seed_bytes_hex=*/kMlDsa44ExpectedSeedBytesHex,
          /*private_key_pem=*/kMlDsa44PrivateKeyPem,
          /*public_key_pem=*/kMlDsa44PublicKeyPem,
      },
      MlDsaPrivateKeyTestParams{
          /*test_name=*/"ML_DSA_65",
          /*parameters=*/*mldsa65_params,
          /*expected_seed_bytes_hex=*/kMlDsa65ExpectedSeedBytesHex,
          /*private_key_pem=*/kMlDsa65PrivateKeyPem,
          /*public_key_pem=*/kMlDsa65PublicKeyPem,
      },
      MlDsaPrivateKeyTestParams{
          /*test_name=*/"ML_DSA_87",
          /*parameters=*/*mldsa87_params,
          /*expected_seed_bytes_hex=*/kMlDsa87ExpectedSeedBytesHex,
          /*private_key_pem=*/kMlDsa87PrivateKeyPem,
          /*public_key_pem=*/kMlDsa87PublicKeyPem,
      },
  };
}

INSTANTIATE_TEST_SUITE_P(
    MlDsaPrivateKeyTest, MlDsaPrivateKeyTestVectorsTest,
    testing::ValuesIn(GetMlDsaPrivateKeyTestParams()),
    [](const testing::TestParamInfo<MlDsaPrivateKeyTestParams>& info) {
      return info.param.test_name;
    });

// ================== Ed25519 ==================

// Obtained via: openssl genpkey -algorithm ED25519 | openssl pkey -pubout
constexpr absl::string_view kEd25519PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQZgPMtzG3qOa6/pFqQA0D0c9YDk1w6t/SEJa/O92Jbg=
-----END PUBLIC KEY-----
)";

// Extracted from kEd25519PublicKeyPem by decoding base64 and taking the last
// 32 bytes.
constexpr absl::string_view kEd25519PublicKeyBytesHex =
    "41980f32dcc6dea39aebfa45a900340f473d603935c3ab7f48425afcef7625b8";

// Generated with:
// openssl genpkey -algorithm ed25519 | openssl pkey -pubout
constexpr absl::string_view kEd25519PrivateKeyPem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIEi4HkntDhMSTvueyGqMkz7JBBAjYoejWoQ8g5mt5oO5\n"
    "-----END PRIVATE KEY-----\n";

constexpr absl::string_view kEd25519PublicKeyPemForPrivateKeyTest =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAjEi9PyvpouGb4mRRG77VeBY8p9PMLvrUbATHJZYkYto=\n"
    "-----END PUBLIC KEY-----\n";

TEST(PemParserEd25519Test, PemToSignaturePublicKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  std::string expected_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes(kEd25519PublicKeyBytesHex, &expected_bytes));
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519PublicKey, public_key,
      Ed25519PublicKey::Create(params, expected_bytes,
                               /*id_requirement=*/std::nullopt,
                               GetPartialKeyAccess()));

  TINK_ASSERT_OK_AND_ASSIGN(Ed25519PublicKey, parsed_public_key,
                            PemToEd25519PublicKey(kEd25519PublicKeyPem, params,
                                                  GetPartialKeyAccess()));
  EXPECT_EQ(parsed_public_key, public_key);
}

TEST(PemParserEd25519Test, PemToSignaturePublicKeyEd25519FailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  EXPECT_THAT(
      PemToEd25519PublicKey("invalid pem", params, GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEd25519Test, PemToSignaturePublicKeyEd25519FailsForRsaPublicKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  // A 2048-bit RSA public key PEM.
  constexpr absl::string_view kLocalRsaPublicKeyPem =
      R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAZ+qQOMJLBjysYUayZ5
NJnMipOYUghZa5cArNTlGlgEEzFsxazFtJnUeBQhupsNivda5WthedWn/CCY8vxN
NmpqQWaxXyJU2xyzzl3Uq4C9i9Wttd80tgLDGdTQBCmcBuXiQ3/WJuKEwp7redGC
C4MLcGBy76L9HIiY0eqvOfufVM52ceorVRKkKQ0+xYu0Fjmhm+ZjCxwnBZuaMlBb
68b0KzAfn7LPK2JMG2WYcCu+rtOLX9mUHWYf9q3KZf+yUdHzFLztCGH6MOxnbiEp
5ay6A6bLdZT5PGDO+bKu7kXtxqrdMfhB7h83/WPM/zzruwGKPWMbPUmKeTSHBLtB
nwIDAQAB
-----END PUBLIC KEY-----
)";

  EXPECT_THAT(PemToEd25519PublicKey(kLocalRsaPublicKeyPem, params,
                                    GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEd25519Test,
     PemToSignaturePublicKeyEd25519FailsForX25519PublicKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  // An X25519 public key PEM.
  constexpr absl::string_view kX25519PublicKeyPem =
      "-----BEGIN PUBLIC KEY-----\n"
      "MCowBQYDK2VuAyEAIrWkPFkg8HmlO4r7BTtJeW9hCdFaPj3QwmIdn7PGjRs=\n"
      "-----END PUBLIC KEY-----\n";

  EXPECT_THAT(
      PemToEd25519PublicKey(kX25519PublicKeyPem, params, GetPartialKeyAccess()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEd25519Test,
     PemToSignaturePrivateKeyEd25519SuccessAndSignVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519PrivateKey, priv_key,
      PemToEd25519PrivateKey(kEd25519PrivateKeyPem, params,
                             InsecureSecretKeyAccess::Get(),
                             GetPartialKeyAccess()));
  EXPECT_EQ(priv_key.GetPublicKey().GetParameters(), params);

  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              priv_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "some test message to sign";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle,
      handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()));

  // Verify using the public key obtained from the private key.
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeyVerify>, verifier,
      pub_handle->GetPrimitive<PublicKeyVerify>(ConfigGlobalRegistry()));
  EXPECT_THAT(verifier->Verify(signature, kMessage), IsOk());

  // Use the public key obtained from PEM.
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519PublicKey, pub_key_from_pem,
      PemToEd25519PublicKey(kEd25519PublicKeyPemForPrivateKeyTest, params,
                            GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, pub_handle_from_pem,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              pub_key_from_pem, KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>, verifier_from_pem,
                            pub_handle_from_pem.GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_pem->Verify(signature, kMessage), IsOk());
}

TEST(PemParserEd25519Test, PemToSignaturePrivateKeyFailsForPublicKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToEd25519PrivateKey(kEd25519PublicKeyPemForPrivateKeyTest,
                                     params, InsecureSecretKeyAccess::Get(),
                                     GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEd25519Test,
     PemToSignaturePrivateKeyEd25519FailsForX25519PrivateKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  // An X25519 private key PEM.
  constexpr absl::string_view kX25519PrivateKeyPem =
      "-----BEGIN PRIVATE KEY-----\n"
      "MC4CAQAwBQYDK2VuBCIEIMip1akQka2FHGaLBzbByaApNsDTrWJnCFgIgEe6BXR1\n"
      "-----END PRIVATE KEY-----\n";

  EXPECT_THAT(PemToEd25519PrivateKey(kX25519PrivateKeyPem, params,
                                     InsecureSecretKeyAccess::Get(),
                                     GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEd25519Test, PemToSignaturePublicKeyFailsForPrivateKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      Ed25519Parameters, params,
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix));

  EXPECT_THAT(PemToEd25519PublicKey(kEd25519PrivateKeyPem, params,
                                    GetPartialKeyAccess()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// ================== RSA ==================

// Obtained via: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
constexpr absl::string_view kRsaPrivateKeyPem =
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
-----END PRIVATE KEY-----
)";

// Extracted from kRsaPrivateKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,256):
// NOLINTBEGIN
// SEQUENCE
//   INTEGER 00
//   SEQUENCE
//     ObjectIdentifier rsaEncryption (1 2 840 113549 1 1 1)
//     NULL
//   OCTETSTRING, encapsulates
//     SEQUENCE
//       INTEGER 00
//       INTEGER
//       00bc067ea9038c24b063cac6146b26793499cc8a93985208596b9700acd4e51a580413316cc5acc5b499d4781421ba9b0d8af75ae56b6179d5a7fc2098f2fc4d366a6a4166b15f2254db1cb3ce5dd4ab80bd8bd5adb5df34b602c319d4d004299c06e5e2437fd626e284c29eeb79d1820b830b706072efa2fd1c8898d1eaaf39..(total
//       257bytes)..9f54ce7671ea2b5512a4290d3ec58bb41639a19be6630b1c27059b9a32505bebc6f42b301f9fb2cf2b624c1b6598702bbeaed38b5fd9941d661ff6adca65ffb251d1f314bced0861fa30ec676e2129e5acba03a6cb7594f93c60cef9b2aeee45edc6aadd31f841ee1f37fd63ccff3cebbb018a3d631b3d498a79348704bb419f
//       INTEGER 010001
//       INTEGER
//       718b1a81c5faa34d4175fa17ea7cd944c27b9a5376f052ca6d064b0a13a6263a707b86a540da0ca9fb1b2b483cf60b1c2a872504d5cb8f5f4e8a1ac54236ca09ca4950254b873f9c2e952e9fb859ed17595f50320e5a33e295d86b88eff5138b7d3ee55c0d9eacecad6f39b8c95f9340906a1ffa9e6dc7e7418bdb7d28539897297c7da5358867e60dfe8c76fbf5a6a4c064e0f6af1bf3c9640cbee007aea3be81017b726d088b69957b844f951fac323ff3e79fd67daf32a3dce862320ab0f4a78255f740f7381396ab8d55f80c1b38a149f2418a2747795b44b14092fa17d215ae0e33c78997471ab971628b897776a80bbdee7eddf60eca6cecba50f32281
//       INTEGER
//       00e3f152467849f4c2d87f5a6506453878b7547996b14067966e336399e2be6a8c2ea8f065251f05e8bdcde4733d7084523432f3aad6b75990efadbedbce91cb097ce2b85dfa22fd3ca12a86198d76d31009531351f07246937cd7b1d81d3675f8afd759d1279edb1306e12f757baf368e265fb429775b1b4d16d88a7b009f00c7
//       INTEGER
//       00d32b57f3d29f741c33ccf95d98b93b4efd56af0f9bc98f9089d8761ecccf65e0ba7feebfbef8fce3bb38a4a5f9614d47a28f137238518ab47f0a12912dc951b1d540632bc570338b17ee4f866767b7ba98ac6a057f1a2b27101ee584e9e82d4a83f31ef14d11f1d9105dc38e3052a506982ff3679e760c7ad186f361284c9069
//       INTEGER
//       00c536bf9694f077c2350a4aad69756e5c9351953959f67d295c033e43a0385b7b19cbb4e1edf21f6cb4fb7492782fe76c30197d54ec1d0a7329cbcb7be607a2017d79b3462beb25ead50e33a3dc0f58a1614fed4151a5ad8661d744d9d4bc8fe9304a443d7fe823671ce6abe71bb206a38a73f72e8143e4251885159b42784f75
//       INTEGER
//       367023116147e807e936bb466cbbbbd5662bf59f617af9beba3a8a60f04dbb26cf0d72000e7c63bd55a389969c0e807caa24964fc8c304adf95e20613adb7e6b08ddbb732a47fd91ab0ead83a99eac57b74a235edd6062a5845b62b1fc16f5ae130c16fafff25355b1096b0379e3a45569e05ab068c267ff358ac3ad55553f99
//       INTEGER
//       3a47030f3e868a1457f0290ae5e8e1a95fef23f9b8d90b20d8e75d138c94bc01e9922d60126a8af6c7142ebb32ced086b52cf1fa5dd389bce61bf6c66ec4c9d47cd08a8b5aad7d9f48202003cc19bdce05d1e41b568e60c43aec44a23031282bd46ac47ea77ddf2b8a303a784e27c73f9e0dd5b5f93e7be71361c2db675130d4
// NOLINTEND
constexpr absl::string_view kRsaModulusHex =
    "00bc067ea9038c24b063cac6146b26793499cc8a93985208596b9700acd4e51a580413"
    "316cc5acc5b499d4781421ba9b0d8af75ae56b6179d5a7fc2098f2fc4d366a6a4166b1"
    "5f2254db1cb3ce5dd4ab80bd8bd5adb5df34b602c319d4d004299c06e5e2437fd626e2"
    "84c29eeb79d1820b830b706072efa2fd1c8898d1eaaf39fb9f54ce7671ea2b5512a429"
    "0d3ec58bb41639a19be6630b1c27059b9a32505bebc6f42b301f9fb2cf2b624c1b6598"
    "702bbeaed38b5fd9941d661ff6adca65ffb251d1f314bced0861fa30ec676e2129e5ac"
    "ba03a6cb7594f93c60cef9b2aeee45edc6aadd31f841ee1f37fd63ccff3cebbb018a3d"
    "631b3d498a79348704bb419f";
constexpr absl::string_view kRsaPrivateExponentHex =
    "718b1a81c5faa34d4175fa17ea7cd944c27b9a5376f052ca6d064b0a13a6263a707b86"
    "a540da0ca9fb1b2b483cf60b1c2a872504d5cb8f5f4e8a1ac54236ca09ca4950254b87"
    "3f9c2e952e9fb859ed17595f50320e5a33e295d86b88eff5138b7d3ee55c0d9eacecad"
    "6f39b8c95f9340906a1ffa9e6dc7e7418bdb7d28539897297c7da5358867e60dfe8c76"
    "fbf5a6a4c064e0f6af1bf3c9640cbee007aea3be81017b726d088b69957b844f951fac"
    "323ff3e79fd67daf32a3dce862320ab0f4a78255f740f7381396ab8d55f80c1b38a149"
    "f2418a2747795b44b14092fa17d215ae0e33c78997471ab971628b897776a80bbdee7e"
    "ddf60eca6cecba50f32281";
constexpr absl::string_view kRsaPHex =
    "00e3f152467849f4c2d87f5a6506453878b7547996b14067966e336399e2be6a8c2ea8"
    "f065251f05e8bdcde4733d7084523432f3aad6b75990efadbedbce91cb097ce2b85dfa"
    "22fd3ca12a86198d76d31009531351f07246937cd7b1d81d3675f8afd759d1279edb13"
    "06e12f757baf368e265fb429775b1b4d16d88a7b009f00c7";
constexpr absl::string_view kRsaQHex =
    "00d32b57f3d29f741c33ccf95d98b93b4efd56af0f9bc98f9089d8761ecccf65e0ba7f"
    "eebfbef8fce3bb38a4a5f9614d47a28f137238518ab47f0a12912dc951b1d540632bc5"
    "70338b17ee4f866767b7ba98ac6a057f1a2b27101ee584e9e82d4a83f31ef14d11f1d9"
    "105dc38e3052a506982ff3679e760c7ad186f361284c9069";
constexpr absl::string_view kRsaDPHex =
    "00c536bf9694f077c2350a4aad69756e5c9351953959f67d295c033e43a0385b7b19cb"
    "b4e1edf21f6cb4fb7492782fe76c30197d54ec1d0a7329cbcb7be607a2017d79b3462b"
    "eb25ead50e33a3dc0f58a1614fed4151a5ad8661d744d9d4bc8fe9304a443d7fe82367"
    "1ce6abe71bb206a38a73f72e8143e4251885159b42784f75";
constexpr absl::string_view kRsaDQHex =
    "367023116147e807e936bb466cbbbbd5662bf59f617af9beba3a8a60f04dbb26cf0d72"
    "000e7c63bd55a389969c0e807caa24964fc8c304adf95e20613adb7e6b08ddbb732a47"
    "fd91ab0ead83a99eac57b74a235edd6062a5845b62b1fc16f5ae130c16fafff25355b1"
    "096b0379e3a45569e05ab068c267ff358ac3ad55553f99";
constexpr absl::string_view kRsaCoefficientHex =
    "3a47030f3e868a1457f0290ae5e8e1a95fef23f9b8d90b20d8e75d138c94bc01e9922d"
    "60126a8af6c7142ebb32ced086b52cf1fa5dd389bce61bf6c66ec4c9d47cd08a8b5aad"
    "7d9f48202003cc19bdce05d1e41b568e60c43aec44a23031282bd46ac47ea77ddf2b8a"
    "303a784e27c73f9e0dd5b5f93e7be71361c2db675130d4";

// echo "<kRsaPrivateKeyPem>" | openssl rsa -traditional
constexpr absl::string_view kRsaPrivateKeyPemInPkcs1Format =
    R"(-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvAZ+qQOMJLBjysYUayZ5NJnMipOYUghZa5cArNTlGlgEEzFs
xazFtJnUeBQhupsNivda5WthedWn/CCY8vxNNmpqQWaxXyJU2xyzzl3Uq4C9i9Wt
td80tgLDGdTQBCmcBuXiQ3/WJuKEwp7redGCC4MLcGBy76L9HIiY0eqvOfufVM52
ceorVRKkKQ0+xYu0Fjmhm+ZjCxwnBZuaMlBb68b0KzAfn7LPK2JMG2WYcCu+rtOL
X9mUHWYf9q3KZf+yUdHzFLztCGH6MOxnbiEp5ay6A6bLdZT5PGDO+bKu7kXtxqrd
MfhB7h83/WPM/zzruwGKPWMbPUmKeTSHBLtBnwIDAQABAoIBAHGLGoHF+qNNQXX6
F+p82UTCe5pTdvBSym0GSwoTpiY6cHuGpUDaDKn7GytIPPYLHCqHJQTVy49fTooa
xUI2ygnKSVAlS4c/nC6VLp+4We0XWV9QMg5aM+KV2GuI7/UTi30+5VwNnqzsrW85
uMlfk0CQah/6nm3H50GL230oU5iXKXx9pTWIZ+YN/ox2+/WmpMBk4PavG/PJZAy+
4Aeuo76BAXtybQiLaZV7hE+VH6wyP/Pnn9Z9rzKj3OhiMgqw9KeCVfdA9zgTlquN
VfgMGzihSfJBiidHeVtEsUCS+hfSFa4OM8eJl0cauXFii4l3dqgLve5+3fYOymzs
ulDzIoECgYEA4/FSRnhJ9MLYf1plBkU4eLdUeZaxQGeWbjNjmeK+aowuqPBlJR8F
6L3N5HM9cIRSNDLzqta3WZDvrb7bzpHLCXziuF36Iv08oSqGGY120xAJUxNR8HJG
k3zXsdgdNnX4r9dZ0See2xMG4S91e682jiZftCl3WxtNFtiKewCfAMcCgYEA0ytX
89KfdBwzzPldmLk7Tv1Wrw+byY+Qidh2HszPZeC6f+6/vvj847s4pKX5YU1Hoo8T
cjhRirR/ChKRLclRsdVAYyvFcDOLF+5Phmdnt7qYrGoFfxorJxAe5YTp6C1Kg/Me
8U0R8dkQXcOOMFKlBpgv82eedgx60YbzYShMkGkCgYEAxTa/lpTwd8I1CkqtaXVu
XJNRlTlZ9n0pXAM+Q6A4W3sZy7Th7fIfbLT7dJJ4L+dsMBl9VOwdCnMpy8t75gei
AX15s0Yr6yXq1Q4zo9wPWKFhT+1BUaWthmHXRNnUvI/pMEpEPX/oI2cc5qvnG7IG
o4pz9y6BQ+QlGIUVm0J4T3UCgYA2cCMRYUfoB+k2u0Zsu7vVZiv1n2F6+b66Oopg
8E27Js8NcgAOfGO9VaOJlpwOgHyqJJZPyMMErfleIGE6235rCN27cypH/ZGrDq2D
qZ6sV7dKI17dYGKlhFtisfwW9a4TDBb6//JTVbEJawN546RVaeBasGjCZ/81isOt
VVU/mQKBgDpHAw8+hooUV/ApCuXo4alf7yP5uNkLINjnXROMlLwB6ZItYBJqivbH
FC67Ms7QhrUs8fpd04m85hv2xm7EydR80IqLWq19n0ggIAPMGb3OBdHkG1aOYMQ6
7ESiMDEoK9RqxH6nfd8rijA6eE4nxz+eDdW1+T575xNhwttnUTDU
-----END RSA PRIVATE KEY-----
)";

// Obtained via: echo "<kRsaPrivateKeyPem>" | openssl pkey -pubout
constexpr absl::string_view kRsaPublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAZ+qQOMJLBjysYUayZ5
NJnMipOYUghZa5cArNTlGlgEEzFsxazFtJnUeBQhupsNivda5WthedWn/CCY8vxN
NmpqQWaxXyJU2xyzzl3Uq4C9i9Wttd80tgLDGdTQBCmcBuXiQ3/WJuKEwp7redGC
C4MLcGBy76L9HIiY0eqvOfufVM52ceorVRKkKQ0+xYu0Fjmhm+ZjCxwnBZuaMlBb
68b0KzAfn7LPK2JMG2WYcCu+rtOLX9mUHWYf9q3KZf+yUdHzFLztCGH6MOxnbiEp
5ay6A6bLdZT5PGDO+bKu7kXtxqrdMfhB7h83/WPM/zzruwGKPWMbPUmKeTSHBLtB
nwIDAQAB
-----END PUBLIC KEY-----
)";

// Modified from kRsaPrivateKeyPem to use sha256WithRSAEncryption OID
// (1.2.840.113549.1.1.11). Generation process:
// 1. Take kRsaPrivateKeyPem and decode its Base64 body to DER.
// 2. Find the rsaEncryption OID DER bytes: 06 09 2a 86 48 86 f7 0d 01 01 01
// 3. Replace them with sha256WithRSAEncryption OID DER bytes: 06 09 2a 86 48 86
// f7 0d 01 01 0b
// 4. Base64 encode the modified DER and wrap with PEM headers.
//
// This works because both OIDs have the same length (9 bytes value), so no
// ASN.1 length fields need to be updated.
constexpr absl::string_view kRsaPrivateKeyPemWithSha256Oid =
    R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQsFAASCBKcwggSjAgEAAoIBAQC8Bn6pA4wksGPK
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
-----END PRIVATE KEY-----
)";

RsaSsaPssPrivateKey CreateRsaPssPrivateKeyFromTestVector(
    const RsaSsaPssParameters& params) {
  std::string n, p, q, dp, dq, d, q_inv;
  ABSL_CHECK(absl::HexStringToBytes(kRsaModulusHex, &n));
  ABSL_CHECK(absl::HexStringToBytes(kRsaPHex, &p));
  ABSL_CHECK(absl::HexStringToBytes(kRsaQHex, &q));
  ABSL_CHECK(absl::HexStringToBytes(kRsaDPHex, &dp));
  ABSL_CHECK(absl::HexStringToBytes(kRsaDQHex, &dq));
  ABSL_CHECK(absl::HexStringToBytes(kRsaPrivateExponentHex, &d));
  ABSL_CHECK(absl::HexStringToBytes(kRsaCoefficientHex, &q_inv));

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      params, BigInteger(n),
      /*id_requirement=*/std::nullopt, GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(BigInteger(p).GetValue(),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(BigInteger(q).GetValue(),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(BigInteger(dp).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(BigInteger(dq).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(BigInteger(d).GetValue(),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(BigInteger(q_inv).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

RsaSsaPkcs1PrivateKey CreateRsaPkcs1PrivateKeyFromTestVector(
    const RsaSsaPkcs1Parameters& params) {
  std::string n, p, q, dp, dq, d, q_inv;
  ABSL_CHECK(absl::HexStringToBytes(kRsaModulusHex, &n));
  ABSL_CHECK(absl::HexStringToBytes(kRsaPHex, &p));
  ABSL_CHECK(absl::HexStringToBytes(kRsaQHex, &q));
  ABSL_CHECK(absl::HexStringToBytes(kRsaDPHex, &dp));
  ABSL_CHECK(absl::HexStringToBytes(kRsaDQHex, &dq));
  ABSL_CHECK(absl::HexStringToBytes(kRsaPrivateExponentHex, &d));
  ABSL_CHECK(absl::HexStringToBytes(kRsaCoefficientHex, &q_inv));

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(params, BigInteger(n),
                                   /*id_requirement=*/std::nullopt,
                                   GetPartialKeyAccess());
  ABSL_CHECK_OK(public_key);

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedData(BigInteger(p).GetValue(),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedData(BigInteger(q).GetValue(),
                                    InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedData(BigInteger(dp).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedData(BigInteger(dq).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedData(BigInteger(d).GetValue(),
                                             InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedData(BigInteger(q_inv).GetValue(),
                                            InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ABSL_CHECK_OK(private_key);
  return *private_key;
}

TEST(PemParserRsaPssTest, PemToSignaturePublicKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPssPrivateKey private_key =
      CreateRsaPssPrivateKeyFromTestVector(params);

  EXPECT_THAT(
      PemToRsaSsaPssPublicKey(kRsaPublicKeyPem, params, GetPartialKeyAccess()),
      IsOkAndHolds(Eq(private_key.GetPublicKey())));
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPssPrivateKey private_key =
      CreateRsaPssPrivateKeyFromTestVector(params);

  EXPECT_THAT(PemToRsaSsaPssPrivateKey(kRsaPrivateKeyPem, params,
                                       InsecureSecretKeyAccess::Get(),
                                       GetPartialKeyAccess()),
              IsOkAndHolds(Eq(private_key)));
}

TEST(PemParserRsaPssTest, SignAndVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssPrivateKey, private_key,
      PemToRsaSsaPssPrivateKey(kRsaPrivateKeyPem, params,
                               InsecureSecretKeyAccess::Get(),
                               GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, private_handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              private_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      private_handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "test message";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  // Verify using the public key obtained from the private key.
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle_from_priv,
      private_handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()));
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>,
                            verifier_from_priv,
                            pub_handle_from_priv->GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_priv->Verify(signature, kMessage), IsOk());

  // Verify using the public key obtained from PEM.
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssPublicKey, public_key_from_pem,
      PemToRsaSsaPssPublicKey(kRsaPublicKeyPem, params, GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, pub_handle_from_pem,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              public_key_from_pem, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>, verifier_from_pem,
                            pub_handle_from_pem.GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_pem->Verify(signature, kMessage), IsOk());
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKeyPkcs1Legacy) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPssPrivateKey private_key =
      CreateRsaPssPrivateKeyFromTestVector(params);

  EXPECT_THAT(PemToRsaSsaPssPrivateKey(kRsaPrivateKeyPemInPkcs1Format, params,
                                       InsecureSecretKeyAccess::Get(),
                                       GetPartialKeyAccess()),
              IsOkAndHolds(private_key));
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKeyRsaPssMismatchedModulusSize) {
  // Parameters have modulus size of 4096, but PEM key has modulus size of 2048.
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPssPrivateKey(kRsaPrivateKeyPem, params,
                                       InsecureSecretKeyAccess::Get(),
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKeyRsaPssFailsForEcdsaKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPssPrivateKey(kP256PrivateKeyPem, params,
                                       InsecureSecretKeyAccess::Get(),
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKeyRsaPssFailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPssPrivateKey(
          "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
          params, InsecureSecretKeyAccess::Get(), GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePrivateKeyRsaPssFailsForPublicKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPssPrivateKey(kP256PublicKeyPem, params,
                                       InsecureSecretKeyAccess::Get(),
                                       GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePublicKeyRsaPssMismatchedModulusSize) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPssPublicKey(kRsaPublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePublicKeyRsaPssFailsForEcdsaKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPssPublicKey(kP256PublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePublicKeyRsaPssFailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPssPublicKey(
          "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
          params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPssTest, PemToSignaturePublicKeyRsaPssFailsForPrivateKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPssParameters, params,
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPssPublicKey(kRsaPrivateKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePublicKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPkcs1PrivateKey private_key =
      CreateRsaPkcs1PrivateKeyFromTestVector(params);

  EXPECT_THAT(PemToRsaSsaPkcs1PublicKey(kRsaPublicKeyPem, params,
                                        GetPartialKeyAccess()),
              IsOkAndHolds(Eq(private_key.GetPublicKey())));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePrivateKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPkcs1PrivateKey private_key =
      CreateRsaPkcs1PrivateKeyFromTestVector(params);

  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kRsaPrivateKeyPem, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess()),
              IsOkAndHolds(Eq(private_key)));
}

TEST(PemParserRsaPkcs1Test, SignAndVerify) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1PrivateKey, private_key,
      PemToRsaSsaPkcs1PrivateKey(kRsaPrivateKeyPem, params,
                                 InsecureSecretKeyAccess::Get(),
                                 GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, private_handle,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              private_key, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<PublicKeySign>, signer,
      private_handle.GetPrimitive<PublicKeySign>(ConfigGlobalRegistry()));

  constexpr absl::string_view kMessage = "test message";
  TINK_ASSERT_OK_AND_ASSIGN(std::string, signature, signer->Sign(kMessage));

  // Verify using the public key obtained from the private key.
  TINK_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<KeysetHandle>, pub_handle_from_priv,
      private_handle.GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()));
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>,
                            verifier_from_priv,
                            pub_handle_from_priv->GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_priv->Verify(signature, kMessage), IsOk());

  // Verify using the public key obtained from PEM.
  TINK_ASSERT_OK_AND_ASSIGN(RsaSsaPkcs1PublicKey, public_key_from_pem,
                            PemToRsaSsaPkcs1PublicKey(kRsaPublicKeyPem, params,
                                                      GetPartialKeyAccess()));
  TINK_ASSERT_OK_AND_ASSIGN(
      KeysetHandle, pub_handle_from_pem,
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
              public_key_from_pem, KeyStatus::kEnabled, /*is_primary=*/true))
          .Build());
  TINK_ASSERT_OK_AND_ASSIGN(std::unique_ptr<PublicKeyVerify>, verifier_from_pem,
                            pub_handle_from_pem.GetPrimitive<PublicKeyVerify>(
                                ConfigGlobalRegistry()));
  EXPECT_THAT(verifier_from_pem->Verify(signature, kMessage), IsOk());
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePrivateKeyPkcs1Legacy) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());
  RsaSsaPkcs1PrivateKey private_key =
      CreateRsaPkcs1PrivateKeyFromTestVector(params);

  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kRsaPrivateKeyPem, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess()),
              IsOkAndHolds(private_key));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePrivateKeyWithSha256OidFails) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  // This fails because BoringSSL does not support sha256WithRSAEncryption OID
  // (1.2.840.113549.1.1.11) by default.
  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kRsaPrivateKeyPemWithSha256Oid, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test,
     PemToSignaturePrivateKeyRsaPkcs1MismatchedModulusSize) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kRsaPrivateKeyPem, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePrivateKeyRsaPkcs1FailsForEcdsaKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kP256PrivateKeyPem, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test,
     PemToSignaturePrivateKeyRsaPkcs1FailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPkcs1PrivateKey(
          "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----",
          params, InsecureSecretKeyAccess::Get(), GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test,
     PemToSignaturePrivateKeyRsaPkcs1FailsForPublicKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPkcs1PrivateKey(kP256PublicKeyPem, params,
                                         InsecureSecretKeyAccess::Get(),
                                         GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test,
     PemToSignaturePublicKeyRsaPkcs1MismatchedModulusSize) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(4096)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPkcs1PublicKey(kRsaPublicKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePublicKeyRsaPkcs1FailsForEcdsaKey) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPkcs1PublicKey(kP256PublicKeyPem, params,
                                        GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test, PemToSignaturePublicKeyRsaPkcs1FailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(
      PemToRsaSsaPkcs1PublicKey(
          "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
          params, GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserRsaPkcs1Test,
     PemToSignaturePublicKeyRsaPkcs1FailsForPrivateKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      RsaSsaPkcs1Parameters, params,
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build());

  EXPECT_THAT(PemToRsaSsaPkcs1PublicKey(kRsaPrivateKeyPem, params,
                                        GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace tink_pem
