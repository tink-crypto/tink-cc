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
#include "tink/config/global_registry.h"
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
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_config.h"

namespace tink_pem {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::BigInteger;
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
using ::crypto::tink::KeyGenConfigGlobalRegistry;
using ::crypto::tink::KeysetHandle;
using ::crypto::tink::KeysetHandleBuilder;
using ::crypto::tink::KeyStatus;
using ::crypto::tink::MlDsaParameters;
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

// Obtained via: openssl genpkey -algorithm ML-DSA-44 | openssl pkey -pubout
constexpr absl::string_view kMlDsa44PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhANeytHJUquDbReeTDUqY0sl9jxOX0Xidr6Fw
JLMW6b7JT8mUbULxm3mnQTu6oz5xSctC7VEVaTrAQfrLmIretf4OHYYxGEmVtZLD
l9IpTi4U+QqkFLo4JomaxD9MzKy8JumoMrlRGNXLQzy++WYLABOOCBf2HnYsonTD
atVU6yKqwRYuSrAay6HjjE79j4C2WzM9D3LlXf5xzpweu5iJ58VhBsD9c4A6Kuz+
r97XqjyyztpU0SvYzTanjPl1lDtHq9JeiArEUuV0LtHo0agq+oblkMdYwVrk0oQN
kryhpQkPQElll/yn2LlRPxob2m6VCqqY3kZ1B9Sk9aTwWZIWWCw1cvYu2okFqzWB
ZwxKAnd6M+DKcpX9j0/20aCjp2g9ZfX19/xg2gI+gmxfkhRMAvfRuhB1mHVT6pNn
/NdtmQt/qZzUWv24g21D5Fn1GH3wWEeXCaAepoNZNfpwRgmQzT3BukAbqUurHd5B
rGerMxncrKBgSNTE7vJ+4TqcF9BTj0MPLWQtwkFWYN54h32NirxyUjl4wELkKF9D
GYRsRBJiQpdoRMEOVWuiFbWnGeWdDGsqltOYWQcf3MLN51JKe+2uVOhbMY6FTo/i
svPt+slxkSgnCq/R5QRMOk/a/Z/zH5B4S46ORZYUSg2vWGUR09mWK56pWvGXtOX8
YPKx7RXeOlvvX4m9x52RBR2bKBbnT6VFMe/cHL501EiFf0drzVjyHAtlOzt2pOB2
plWaMCcYVVzGP3SFmqurkl8COGHKjND3utsocfZ9VTJtdFETWtRfShumkRj7ssij
DuyTku8/l3Bmya3VxxDMZHsVFNIX2VjHAXw+kP0gwE5nS5BIbpNwoxoAHTL0c5ee
SQZ0nn5Hf6C3RQj4pfI3gxK4PCW9OIygsP/3R4uvQrcWZ+2qyXxGsSlkPlhuWwVa
DCEZRtTzbmdb7Vhg+gQqMV2YJhZNapI3w1pfv0lUkKW9TfJIuVxKrneEtgVnMWas
QkW1tLCCoJ6TI+YvIHjFt2eDRG3v1zatOjcC1JsImESQCmGDM5e8RBmzDXqXoLOH
wZEUdMTUG1PjKpd6y28Op122W7OeWecB52lX3vby1EVZwxp3EitSBOO1whnxaIsU
7QvAuAGz5ugtzUPpwOn0F0TNmBW9G8iCDYuxI/BPrNGxtoXdWisbjbvz7ZM2cPCV
oYC08ZLQixC4+rvfzCskUY4y7qCl4MkEyoRHgAg/OwzS0Li2r2e8NVuUlAJdx7Cn
j6gOOi2/61EyiFHWB4GY6Uk2Ua54fsAlH5Irow6fUd9iptcnhM890gU5MXbfoySl
Er2Ulwo23TSlFKhnkfDrNvAUWwmrZGUbSgMTsplhGiocSIkWJ1mHaKMRQGC6RENI
bfUVIqHOiLMJhcIW+ObtF43VZ7MEoNTK+6iCooNC8XqaomrljbYwCD0sNY/fVmw/
XWKkKFZ7yeqM6VyqDzVHSwv6jzOaJQq0388gg76O77wQVeGP4VNw7ssmBWbYP/Br
IRquxDyim1TM0A+IFaJGXvC0ZRXMfkHzEk8J7/9zkwmrWLKaFFmgC85QOOk4yWeP
cusOTuX9quZtn4Vz/Jf8QrSVn0v4th14Qz6GsDNdbpGRxNi/SHs5BcEIz9asJLDO
t9y3z1H4TQ7Wh7lerrHFM8BvDZcCPZKnCCWDe1m6bLfU5WsKh8IDhiro8xW6WSXo
7e+meTaaIgJ2YVHxapZfn4Hs52zAcLVYaeTbl4TPBcgwsyQsgxI=
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa44PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
// SEQUENCE
//   ObjectIdentifier (2 16 840 1 101 3 4 3 17)
// BITSTRING
// 00d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312
// NOLINTEND
constexpr absl::string_view kMlDsa44ExpectedBytesHex =
    R"(
d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec9
4fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe
0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26
e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aa
c1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c5
6106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47ab
d25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f
40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c
3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65
f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7f
a99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3d
c1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f
430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c441262
42976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bed
ae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f
90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de
3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58
f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8c
d0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f
977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e93
70a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd38
8ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f3
6e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c
4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd7
36ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d4
1b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b
5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1b
c8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d0
8b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67
bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787e
c0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36
dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c4889162759
8768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0
d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567b
c9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe153
70eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e
41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fd
aae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b
3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d
92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a
2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312
)";

// Obtained via: openssl genpkey -algorithm ML-DSA-65 | openssl pkey -pubout
constexpr absl::string_view kMlDsa65PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
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
HgLy6ERP
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa65PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
//   ObjectIdentifier (2 16 840 1 101 3 4 3 18)
// BITSTRING
// 0048683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb815030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b51b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8af4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef74948804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b38f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5aef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab620aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6aa77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e84aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d09483673265b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b58536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d76bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b8582bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f
// NOLINTEND
constexpr absl::string_view kMlDsa65ExpectedBytesHex =
    R"(
48683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27
d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee
67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de273
0d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16cc
fea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1
e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d59
7dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8
fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d2798
7bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29
afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3
e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d
260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb
5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd
8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b674
2257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8
b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5
c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e0
3445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b07
3873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af85
8dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b
9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a05351
6feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2
310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246
d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe880
14960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab43
0a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72
c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff05
71b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983e
d3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8f
f7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4c
b798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a07e744300
750df1d2c58753389059eafc3d785ccdd31c07648bedc03a5c3b8ad46d064d59
c13d57374729fc4e295362e2a5191204530428bc1522afa28ff5fe1655e304ca
5bc8c27ad0e0c6a39dd4df28956c14b38cc93682cefe402bbd5e82d29c464e44
eb5d37b48fc568dfe0cc6e8e16baea05e5135590f19294e73e8367b0216dbb81
5030b9de55913f08039c42351c59e5515dd5af8e089a15e625e8f6dee639386c
46497d7a263288774de581a7de9629b41b4424141f978fb8331208efdec3c6e0
de39bc57063f3dcd6c470373c08891ea29cbc7cc6d6483b8889083ace86aa7b5
1b1c2cfe6e2ad18d97ce36fbc56ea42fae97e6a7ac114864478c366df1ebb1e7
b11a9098504fd5975bdf1f49dc70002b63c1739a9d263fbad4073f6a9f6c2b8a
f4b4c332a103a0cffa5deeb2d062ca3c215fd360026be7c5164f4a4424ef7494
8804d66f46487732c8202c795478647b4ea71d627c086024cca354a41f0877b3
8f19b3774ad2095c8da53b069e21c76ae2d2007e16719ed40080d334f7da52e9
f5a5990439caf083a95b833f02ad10a08c1a6d0f260c007285bd4a2f47703a5a
ef465287d253b18ac22514316210ff566814b10f87a293d6f199d3c3959990d0
c1268b4f50d5f9fcefbbf237bd0c28b80182d6659741f14f10bfbb21bba12ab6
20aa2396f56c0686b4ea9017990224216b2fe8ad76c4a9148eef9a86a3635a6a
a77bc1dcfb6fba59a77dfda9b7530dc0ca8648c8d973738e01bab8f08b4905e8
4aa4641bd602410cd97520265f2f231f2b35e15eb2fa04d2bd94d5a77abaf1e0
e161010a990087f5b46ea988b2bc0512fda0fa923dadd6c45c5301d094836732
65b5ab2e10f4ba520f6bbad564a5c3d5e27bdb080f7d20e13296a3181954c39c
649c943ebe17df5c1f7aae0a8fe126c477585a5d4d648a0d008b6af5e8cd31be
69a9296d4f3fd25ed86f221e4b93f65f5929967533624b9235750c30707550b5
8536d109a7131c5a5bbe4a5715567c12534aec7660761eebb9fae2891c774589
b80e566ad557ddef7367196b7227ea9870ef09ddfec79d6b9319a6879b5205d7
6bf7aba5acf33afb59d17fc54e68383d6be5a08e9b66da53dcde008bb294b858
2bd132cdcc49959fdbc21e52721880c8ad0352c79f03a43bbd84c4cdfdc6c529
005e1e7cd9a349a7168a35569ba5dea818968d5a91466bd6e64e20bf62417198
afc4e81c28dd77ed4028232398b52fbde86bc84f475b9016710ce2aabc11a06b
4dbac901ec16cf365ca3f2d53813948a693a0f93e79c46ca5d5a6dca3d28ca50
ad18bd13fca55059dd9b185f79f9c47196a4e81b2104bc460a051e02f2e8444f
)";

// Obtained via: openssl genpkey -algorithm ML-DSA-87 | openssl pkey -pubout
constexpr absl::string_view kMlDsa87PublicKeyPem =
    R"(-----BEGIN PUBLIC KEY-----
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
5VvgYiIvi6kKl0BzMmsxISrs4KNKYA==
-----END PUBLIC KEY-----
)";

// Extracted from kMlDsa87PublicKeyPem with
// https://cyberchef.googleplex.com/#recipe=PEM_to_Hex()Parse_ASN.1_hex_string(0,2048):
// NOLINTBEGIN
// SEQUENCE
//   SEQUENCE
//     ObjectIdentifier (2 16 840 1 101 3 4 3 19)
//   BITSTRING
//   009792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afbb13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16cc8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b56b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa91685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd458a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c66509b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe49229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d870f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173ec6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db31714286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc3280a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df080053e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f496468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba570801dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce49731bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77aa5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022be7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e9147054ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca78940852f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a87357487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e85095c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731ab38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f7165f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebaec5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e30ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b0472e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b91001b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a995e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e939528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11cfcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b46500818113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca26087c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c81dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbebbbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e54844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579fa87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb1853d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad875b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60
// NOLINTEND
constexpr absl::string_view kMlDsa87ExpectedBytesHex =
    R"(
9792bcec2f2430686a82fccf3c2f5ff665e771d7ab41b90258cfa7e90ec97124
a73b323b9ba21ab64d767c433f5a521effe18f86e46a188952c4467e048b729e
7fc4d115e7e48da1896d5fe119b10dcddef62cb307954074b42336e52836de61
da941f8d37ea68ac8106fabe19070679af6008537120f70793b8ea9cc0e6e7b7
b4c9a5c7421c60f24451ba1e933db1a2ee16c79559f21b3d1b8305850aa42afb
b13f1f4d5b9f4835f9d87dfceb162d0ef4a7fdc4cba1743cd1c87bb4967da16c
c8764b6569df8ee5bdcbffe9a4e05748e6fdf225af9e4eeb7773b62e8f85f9b5
6b548945551844fbd89806a4ac369bed2d256100f688a6ad5e0a709826dc4449
e91e23c5506e642361ef5a313712f79bc4b3186861ca85a4bab17e7f943d1b8a
333aa3ae7ce16b440d6018f9e04daf5725c7f1a93fad1a5a27b67895bd249aa9
1685de20af32c8b7e268c7f96877d0c85001135a4f0a8f1b8264fa6ebe5a349d
8aecad1a16299ccf2fd9c7b85bace2ced3aa1276ba61ee78ed7e5ca5b67cdd45
8a9354030e6abbbabf56a0a2316fec9dba83b51d42fd3167f1e0f90855d5c665
09b210265dc1e54ec44b43ba7cf9aef118b44d80912ce75166a6651e116cebe4
9229a7062c09931f71abd2293f76f7efc3215ba97800037e58e470bdbbb43c1b
0439eaf79c54d93b44aac9efe9fbe151874cfb2a64cbee28cc4c0fe7775e5d87
0f1c02e5b2e3c5004c995f24c9b779cb753a277d0e71fd425eb6bc2ca56ce129
db51f70740f31e63976b50c7312e9797d78c5b1ac24a5fa347cc916e0a83f5c3
b675cd30b81e3fa10b93444e07397571cce98b28da51db9056bc728c5b0b1181
e2fbd387b4c79ab1a5fefece37167af772ddad14eb4c3982da5a59d0e9eb173e
c6315091170027a3ab5ef6aa129cb8585727b9358a28501d713a72f3f1db3171
4286f9b6408013af06045d75592fc0b7dd47c73ed9c75b11e9d7c69f7cadfc32
80a9062c5273c43be1c34f87448864cea7b5c97d6d32f59bd5f25384653bb5c4
faa45bea8b89402843e645b6b9269e2bd988ddacb033328ffb060450f7df0800
53e6969b251e875ecec32cfc592840d69ab69a75e06b379c535d95266b082f4f
09c93162b33b0d9f7307a4eaaa52104437fed66f8ee3eabbd45d67b25a8133f4
96468b52baffdbfad93eef1a9818b5e42ec722788a3d8d3529fc777d2ba57080
1dfae01ec88302837c1fb9e0355727645ee1046c3f915f6ae82dad4fb6b0356a
46518ffc834155c3b4fe6dafa6cc8a5ccf53c73a0849d8d44f7dcf72754e70e1
b7dfb447bb4ef49d1a718f6171bbce200950e0ce926106b151a3e871d5ce4973
1bd6650a9b0ca972da1c5f136d44820ea6383c08f3b384cf2338e789c513f618
cc5694a6f0cee104511e1ed7c5f23a1ebfd8a0db8424553240156dbf622831b0
c643d1c551b6f3f7a98d29b85c2de05a65fa615eee16495bd90737672115b53e
91c5d90028cf3f1a93953a153de53b44084e9ccff6b736693926daefebb2d77a
a5ad689b92f31686669df16d1715cc58f7a2cfb72dd1a51e92f825993a74022b
e7e9eb6054654457094d14928f20215e7b222ac56b51adbec8d8bdb6983979a7
e3a21b44b5d1518ca97d0b5195f51ed6a24350c89747e1edea51b448e3e91470
54ce927873c90db394d86888e07dff177593d6f79e152302204aeb03be2386af
3e24078bd028b1689f5e147c9f452c8ceb02ec59cc9db63a03576ceeafe98239
023897da0236630a53c0de7f435a19869792fab36e7b9e635760f09069e6432e
700035ac2a02879fff0a1e1bec522047193d94eb5df1efd53eea1144ca789408
52f5ec9727904b366ede4f5e2d331fad5fc282ea2c47e923142771c3dd75a873
57487def99e5f18e9d9ed623c175d02888c51f82c07a80d54716b3c3c2bdbe2e
9f0a9bbaaebeb4d52936876406f5c00e8e4bbd0a5ec05797e6207c5ab6c88f1a
688421bd05a114f4d7de2ac241fa0e8bedff47f762ddcbeaa91004f8d31e8509
5c81054994ad3826e344ba96040810fc0b2ad1de48cfade002c62e5a49a0731a
b38344bc1636df16bf607d56855e56d684003c718e4bad9e5a099979fcddeeb1
c4a7776cd37a3417cb0e184e29ef9bc0e87475ba663be09e00ab562eb7c0f716
5f969a9b42414198ccf1bff2a2c8d689a414ece7662927665689e94db961ebae
c5615cbc1a7895c6851ac961432ff1118d4607d32ef9dc732d51333be4b4d0e3
0ddea784eca8be47e741be9c19631dc470a52ef4dc13a4f3633fd434d787c170
977b417df598e1d0dde506bb71d6f0bc17ec70e3b03cdc1965cb36993f633b04
72e50d0923ac6c66fdf1d3e6459cc121f0f5f94d09e9dbcf5d690e23233838a0
bacb7c638d1b2650a4308cd171b6855126d1da672a6ed85a8d78c286fb56f4ab
3d21497528045c63262c8a42af2f9802c53b7bb8be28e78fe0b5ce45fbb7a1af
1a3b28a8d94b7890e3c882e39bc98e9f0ad76025bf0dd2f00298e7141a226b3d
7cee414f604d1e0ba54d11d5fe58bccea6ad77ad2e8c1caacf32459014b7b910
01b1efa8ad172a523fb8e365b577121bf9fd88a2c60c21e821d7b6acb47a5a99
5e40caced5c223b8fe6de5e18e9d2e5893aefebb7aae7ff1a146260e2f110e93
9528213a0025a38ec79aabc861b25ebc509a4674c132aaacb7e0146f14efd11c
fcaf4caa4f775a716ce325e0a435a4d349d720bcf137450afc45046fc1a1f83a
9d329777a7084e4aadae7122ce97005930528eb3c7f7f1129b372887a371155a
3ba201a25cbf1dcb64e7cdee092c3141fb5550fe3d0dd82e870e578b2b465008
18113b8f6569773c677385b69a42b77dcba7acffd95fd4452e23aaa1d37e1da2
151ea658d40a3596b27ac9f8129dc6cf0643772624b59f4f461230df471ca260
87c3942d5c6687df6082835935a3f87cb762b0c3b1d0dda4a6533965bef1b7b8
292e254c014d090fed857c44c1839c694c0a64e3fad90a11f534722b6ee1574f
2e149d55d744de4887024e08511431c062750e16c74ab9f3242f2db3ffb12a8d
6107faa229d6f6373b07f36d3932b3bdb04c19dd64eadd7f93c3c564c358a1c8
1dcf1c9c31e5b06568f97544c17dc15698c5cb38983a9afc42783faa773a52c9
d8260690be9e3156aa5bc1509dea3f69587695cd6ff172ba83e6a6d8a7d6bbeb
bbcda3672731983f89bc5831dc37c3f3c5c56facc697f3cb20bd5dbadbd702e5
4844ac2f626901fe159db93dfd4773d8fe73562b846c1fc856d1802762840ebc
72d7988bde75cbca70d319d32ce0cc0253bb2ad455723ee0c7f4736ce6e6665c
5aca32a481c53839bc259167b013d0423395eeb9aaaee3206149a7d550d67fc5
fdfe4a8a5c35d2510b664379ab8f72855a2af47abce2a632048eaf89e5cb4a88
debc53a595103acce4f1cff18acff07afe1eb5716aa1e40b63134c3a3ae9579f
a87f515be093c2d29db6d6b65c93661e00636b592704d093cc6716c2342eb185
3d48c85c63ac8a2854462c7b77e7e3bd1eac5bca28ffaa00b5d349f8a547ad87
5b96a8c2b2910c9301309a3f9138a5693111f55b3c009ca947c39dfc82d98eb1
caa4a9cbe885f786fa86e55be062222f8ba90a974073326b31212aece0a34a60
)";

struct MlDsaTestParams {
  std::string test_name;
  MlDsaParameters parameters;
  absl::string_view expected_bytes_hex;
  absl::string_view public_key_pem;
};

using PemParserMlDsaTest = testing::TestWithParam<MlDsaTestParams>;

MlDsaPublicKey CreateMlDsaPublicKeyFromTestVector(
    const MlDsaTestParams& params) {
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

TEST_P(PemParserMlDsaTest, PemToSignaturePublicKey) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  MlDsaTestParams params = GetParam();
  MlDsaPublicKey public_key = CreateMlDsaPublicKeyFromTestVector(params);

  if (IsBoringSsl()) {
    TINK_ASSERT_OK_AND_ASSIGN(
        MlDsaPublicKey, parsed_public_key,
        PemToMlDsaPublicKey(params.public_key_pem, params.parameters,
                            GetPartialKeyAccess()));
    EXPECT_EQ(parsed_public_key, public_key);
  } else {
    EXPECT_THAT(PemToMlDsaPublicKey(params.public_key_pem, params.parameters,
                                    GetPartialKeyAccess())
                    .status(),
                StatusIs(absl::StatusCode::kUnimplemented));
  }
}

TEST(PemParserMlDsaTest, PemToSignaturePublicKeyMlDsaFailsForPrivateKeyPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  absl::StatusCode want_status_code = IsBoringSsl()
                                          ? absl::StatusCode::kInvalidArgument
                                          : absl::StatusCode::kUnimplemented;
  EXPECT_THAT(
      PemToMlDsaPublicKey(kP256PrivateKeyPem, params, GetPartialKeyAccess())
          .status(),
      StatusIs(want_status_code));
}

TEST(PemParserMlDsaTest, PemToSignaturePublicKeyMlDsaFailsForInvalidPem) {
  TINK_ASSERT_OK_AND_ASSIGN(
      MlDsaParameters, params,
      MlDsaParameters::Create(MlDsaParameters::Instance::kMlDsa65,
                              MlDsaParameters::Variant::kNoPrefix));

  absl::StatusCode want_status_code = IsBoringSsl()
                                          ? absl::StatusCode::kInvalidArgument
                                          : absl::StatusCode::kUnimplemented;
  EXPECT_THAT(
      PemToMlDsaPublicKey(
          "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----",
          params, GetPartialKeyAccess())
          .status(),
      StatusIs(want_status_code));
}

std::vector<MlDsaTestParams> GetMlDsaTestParams() {
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
      MlDsaTestParams{
          /*test_name=*/"ML_DSA_44",
          /*parameters=*/*mldsa44_params,
          /*expected_bytes_hex=*/kMlDsa44ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa44PublicKeyPem,
      },
      MlDsaTestParams{
          /*test_name=*/"ML_DSA_65",
          /*parameters=*/*mldsa65_params,
          /*expected_bytes_hex=*/kMlDsa65ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa65PublicKeyPem,
      },
      MlDsaTestParams{
          /*test_name=*/"ML_DSA_87",
          /*parameters=*/*mldsa87_params,
          /*expected_bytes_hex=*/kMlDsa87ExpectedBytesHex,
          /*public_key_pem=*/kMlDsa87PublicKeyPem,
      },
  };
}

INSTANTIATE_TEST_SUITE_P(
    PemParserMlDsaTest, PemParserMlDsaTest,
    testing::ValuesIn(GetMlDsaTestParams()),
    [](const testing::TestParamInfo<MlDsaTestParams>& info) {
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
