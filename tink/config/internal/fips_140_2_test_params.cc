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
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/config/internal/fips_140_2_test_params.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"
#include "tink/aead/aes_eax_parameters.h"
#include "tink/aead/aes_eax_proto_serialization.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/aead/aes_gcm_siv_proto_serialization.h"
#include "tink/aead/x_aes_gcm_parameters.h"
#include "tink/aead/x_aes_gcm_proto_serialization.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/aead/xchacha20_poly1305_proto_serialization.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/aes_cmac_proto_serialization.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/hmac_proto_serialization.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/prf/aes_cmac_prf_proto_serialization.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/prf/hkdf_prf_proto_serialization.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/prf/hmac_prf_proto_serialization.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_proto_serialization.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_proto_serialization.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

// Moves `params` into a `Fips1402TestCase` named `name`. Crashes if `params`
// is not OK: all entries of the tables must be valid `Parameters`.
template <typename P>
Fips1402TestCase MakeTestCase(std::string name, absl::StatusOr<P> params) {
  ABSL_CHECK_OK(params) << "Invalid parameters for test case " << name;
  return Fips1402TestCase{std::move(name),
                          std::make_shared<const P>(*std::move(params))};
}

absl::StatusOr<AesGcmParameters> AesGcm(int key_size,
                                        AesGcmParameters::Variant variant) {
  // The AES-GCM key manager only accepts 12 byte IVs and 16 byte tags.
  return AesGcmParameters::Builder()
      .SetKeySizeInBytes(key_size)
      .SetIvSizeInBytes(12)
      .SetTagSizeInBytes(16)
      .SetVariant(variant)
      .Build();
}

absl::StatusOr<AesCtrHmacAeadParameters> AesCtrHmac(
    int aes_key_size, int hmac_key_size, int iv_size,
    AesCtrHmacAeadParameters::HashType hash, int tag_size,
    AesCtrHmacAeadParameters::Variant variant) {
  return AesCtrHmacAeadParameters::Builder()
      .SetAesKeySizeInBytes(aes_key_size)
      .SetHmacKeySizeInBytes(hmac_key_size)
      .SetIvSizeInBytes(iv_size)
      .SetHashType(hash)
      .SetTagSizeInBytes(tag_size)
      .SetVariant(variant)
      .Build();
}

absl::StatusOr<EcdsaParameters> Ecdsa(
    EcdsaParameters::CurveType curve, EcdsaParameters::HashType hash,
    EcdsaParameters::SignatureEncoding encoding,
    EcdsaParameters::Variant variant) {
  return EcdsaParameters::Builder()
      .SetCurveType(curve)
      .SetHashType(hash)
      .SetSignatureEncoding(encoding)
      .SetVariant(variant)
      .Build();
}

// Uses the default public exponent (F4).
absl::StatusOr<RsaSsaPkcs1Parameters> RsaSsaPkcs1(
    int modulus_size, RsaSsaPkcs1Parameters::HashType hash,
    RsaSsaPkcs1Parameters::Variant variant) {
  return RsaSsaPkcs1Parameters::Builder()
      .SetModulusSizeInBits(modulus_size)
      .SetHashType(hash)
      .SetVariant(variant)
      .Build();
}

// Uses the default public exponent (F4). The RSA-SSA-PSS key manager requires
// the MGF1 hash to be the same as the signature hash.
absl::StatusOr<RsaSsaPssParameters> RsaSsaPss(
    int modulus_size, RsaSsaPssParameters::HashType hash, int salt_length,
    RsaSsaPssParameters::Variant variant) {
  return RsaSsaPssParameters::Builder()
      .SetModulusSizeInBits(modulus_size)
      .SetSigHashType(hash)
      .SetMgf1HashType(hash)
      .SetSaltLengthInBytes(salt_length)
      .SetVariant(variant)
      .Build();
}

}  // namespace

std::vector<Fips1402TestCase> AllowedAeadParameters() {
  return {
      // AES-GCM. The key manager only accepts 16 and 32 byte keys.
      MakeTestCase("AesGcm_Key16_Tink",
                   AesGcm(16, AesGcmParameters::Variant::kTink)),
      MakeTestCase("AesGcm_Key16_Raw",
                   AesGcm(16, AesGcmParameters::Variant::kNoPrefix)),
      MakeTestCase("AesGcm_Key32_Tink",
                   AesGcm(32, AesGcmParameters::Variant::kTink)),
      MakeTestCase("AesGcm_Key32_Raw",
                   AesGcm(32, AesGcmParameters::Variant::kNoPrefix)),
      // AES-CTR-HMAC: AES key size x HMAC hash. HMAC key size, IV size, tag
      // size (10 or max for the hash) and variant are spread across rows.
      MakeTestCase(
          "AesCtrHmac_Aes16_Hmac16_Iv12_Sha1_Tag10_Tink",
          AesCtrHmac(16, 16, 12, AesCtrHmacAeadParameters::HashType::kSha1, 10,
                     AesCtrHmacAeadParameters::Variant::kTink)),
      MakeTestCase(
          "AesCtrHmac_Aes16_Hmac32_Iv16_Sha224_Tag28_Raw",
          AesCtrHmac(16, 32, 16, AesCtrHmacAeadParameters::HashType::kSha224,
                     28, AesCtrHmacAeadParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "AesCtrHmac_Aes16_Hmac16_Iv16_Sha256_Tag32_Tink",
          AesCtrHmac(16, 16, 16, AesCtrHmacAeadParameters::HashType::kSha256,
                     32, AesCtrHmacAeadParameters::Variant::kTink)),
      MakeTestCase(
          "AesCtrHmac_Aes16_Hmac32_Iv12_Sha384_Tag10_Raw",
          AesCtrHmac(16, 32, 12, AesCtrHmacAeadParameters::HashType::kSha384,
                     10, AesCtrHmacAeadParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "AesCtrHmac_Aes16_Hmac16_Iv12_Sha512_Tag64_Tink",
          AesCtrHmac(16, 16, 12, AesCtrHmacAeadParameters::HashType::kSha512,
                     64, AesCtrHmacAeadParameters::Variant::kTink)),
      MakeTestCase(
          "AesCtrHmac_Aes32_Hmac32_Iv16_Sha1_Tag20_Raw",
          AesCtrHmac(32, 32, 16, AesCtrHmacAeadParameters::HashType::kSha1, 20,
                     AesCtrHmacAeadParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "AesCtrHmac_Aes32_Hmac16_Iv12_Sha224_Tag10_Tink",
          AesCtrHmac(32, 16, 12, AesCtrHmacAeadParameters::HashType::kSha224,
                     10, AesCtrHmacAeadParameters::Variant::kTink)),
      MakeTestCase(
          "AesCtrHmac_Aes32_Hmac32_Iv12_Sha256_Tag10_Raw",
          AesCtrHmac(32, 32, 12, AesCtrHmacAeadParameters::HashType::kSha256,
                     10, AesCtrHmacAeadParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "AesCtrHmac_Aes32_Hmac16_Iv16_Sha384_Tag48_Tink",
          AesCtrHmac(32, 16, 16, AesCtrHmacAeadParameters::HashType::kSha384,
                     48, AesCtrHmacAeadParameters::Variant::kTink)),
      MakeTestCase(
          "AesCtrHmac_Aes32_Hmac32_Iv16_Sha512_Tag10_Raw",
          AesCtrHmac(32, 32, 16, AesCtrHmacAeadParameters::HashType::kSha512,
                     10, AesCtrHmacAeadParameters::Variant::kNoPrefix)),
  };
}

std::vector<Fips1402TestCase> AllowedMacParameters() {
  return {
      // HMAC: hash x tag size (10 or max for the hash). Key size and variant
      // are spread across rows.
      MakeTestCase(
          "Hmac_Key16_Sha1_Tag10_Tink",
          HmacParameters::Create(16, 10, HmacParameters::HashType::kSha1,
                                 HmacParameters::Variant::kTink)),
      MakeTestCase(
          "Hmac_Key32_Sha1_Tag20_Raw",
          HmacParameters::Create(32, 20, HmacParameters::HashType::kSha1,
                                 HmacParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "Hmac_Key64_Sha224_Tag10_Raw",
          HmacParameters::Create(64, 10, HmacParameters::HashType::kSha224,
                                 HmacParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "Hmac_Key16_Sha224_Tag28_Tink",
          HmacParameters::Create(16, 28, HmacParameters::HashType::kSha224,
                                 HmacParameters::Variant::kTink)),
      MakeTestCase(
          "Hmac_Key32_Sha256_Tag10_Tink",
          HmacParameters::Create(32, 10, HmacParameters::HashType::kSha256,
                                 HmacParameters::Variant::kTink)),
      MakeTestCase(
          "Hmac_Key64_Sha256_Tag32_Raw",
          HmacParameters::Create(64, 32, HmacParameters::HashType::kSha256,
                                 HmacParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "Hmac_Key16_Sha384_Tag10_Raw",
          HmacParameters::Create(16, 10, HmacParameters::HashType::kSha384,
                                 HmacParameters::Variant::kNoPrefix)),
      MakeTestCase(
          "Hmac_Key32_Sha384_Tag48_Tink",
          HmacParameters::Create(32, 48, HmacParameters::HashType::kSha384,
                                 HmacParameters::Variant::kTink)),
      MakeTestCase(
          "Hmac_Key64_Sha512_Tag10_Tink",
          HmacParameters::Create(64, 10, HmacParameters::HashType::kSha512,
                                 HmacParameters::Variant::kTink)),
      MakeTestCase(
          "Hmac_Key16_Sha512_Tag64_Raw",
          HmacParameters::Create(16, 64, HmacParameters::HashType::kSha512,
                                 HmacParameters::Variant::kNoPrefix)),
  };
}

std::vector<Fips1402TestCase> AllowedPrfParameters() {
  return {
      // HMAC-PRF: one row per hash, key sizes spread across rows.
      MakeTestCase(
          "HmacPrf_Key16_Sha1",
          HmacPrfParameters::Create(16, HmacPrfParameters::HashType::kSha1)),
      MakeTestCase(
          "HmacPrf_Key32_Sha224",
          HmacPrfParameters::Create(32, HmacPrfParameters::HashType::kSha224)),
      MakeTestCase(
          "HmacPrf_Key64_Sha256",
          HmacPrfParameters::Create(64, HmacPrfParameters::HashType::kSha256)),
      MakeTestCase(
          "HmacPrf_Key16_Sha384",
          HmacPrfParameters::Create(16, HmacPrfParameters::HashType::kSha384)),
      MakeTestCase(
          "HmacPrf_Key32_Sha512",
          HmacPrfParameters::Create(32, HmacPrfParameters::HashType::kSha512)),
  };
}

std::vector<Fips1402TestCase> AllowedSignatureParameters() {
  return {
      // ECDSA: (curve, hash) pairs accepted by the key manager x encoding.
      // Variant is spread across rows.
      MakeTestCase("Ecdsa_P256_Sha256_Der_Tink",
                   Ecdsa(EcdsaParameters::CurveType::kNistP256,
                         EcdsaParameters::HashType::kSha256,
                         EcdsaParameters::SignatureEncoding::kDer,
                         EcdsaParameters::Variant::kTink)),
      MakeTestCase("Ecdsa_P256_Sha256_IeeeP1363_Raw",
                   Ecdsa(EcdsaParameters::CurveType::kNistP256,
                         EcdsaParameters::HashType::kSha256,
                         EcdsaParameters::SignatureEncoding::kIeeeP1363,
                         EcdsaParameters::Variant::kNoPrefix)),
      MakeTestCase("Ecdsa_P384_Sha384_Der_Raw",
                   Ecdsa(EcdsaParameters::CurveType::kNistP384,
                         EcdsaParameters::HashType::kSha384,
                         EcdsaParameters::SignatureEncoding::kDer,
                         EcdsaParameters::Variant::kNoPrefix)),
      MakeTestCase("Ecdsa_P384_Sha384_IeeeP1363_Tink",
                   Ecdsa(EcdsaParameters::CurveType::kNistP384,
                         EcdsaParameters::HashType::kSha384,
                         EcdsaParameters::SignatureEncoding::kIeeeP1363,
                         EcdsaParameters::Variant::kTink)),
      MakeTestCase("Ecdsa_P384_Sha512_Der_Tink",
                   Ecdsa(EcdsaParameters::CurveType::kNistP384,
                         EcdsaParameters::HashType::kSha512,
                         EcdsaParameters::SignatureEncoding::kDer,
                         EcdsaParameters::Variant::kTink)),
      MakeTestCase("Ecdsa_P384_Sha512_IeeeP1363_Raw",
                   Ecdsa(EcdsaParameters::CurveType::kNistP384,
                         EcdsaParameters::HashType::kSha512,
                         EcdsaParameters::SignatureEncoding::kIeeeP1363,
                         EcdsaParameters::Variant::kNoPrefix)),
      MakeTestCase("Ecdsa_P521_Sha512_Der_Raw",
                   Ecdsa(EcdsaParameters::CurveType::kNistP521,
                         EcdsaParameters::HashType::kSha512,
                         EcdsaParameters::SignatureEncoding::kDer,
                         EcdsaParameters::Variant::kNoPrefix)),
      MakeTestCase("Ecdsa_P521_Sha512_IeeeP1363_Tink",
                   Ecdsa(EcdsaParameters::CurveType::kNistP521,
                         EcdsaParameters::HashType::kSha512,
                         EcdsaParameters::SignatureEncoding::kIeeeP1363,
                         EcdsaParameters::Variant::kTink)),
      // RSA-SSA-PKCS1: modulus size x hash. Variant is spread across rows. In
      // FIPS mode, Tink only accepts 2048, 3072 and 4096 bit moduli.
      MakeTestCase("RsaSsaPkcs1_2048_Sha256_Tink",
                   RsaSsaPkcs1(2048, RsaSsaPkcs1Parameters::HashType::kSha256,
                               RsaSsaPkcs1Parameters::Variant::kTink)),
      MakeTestCase("RsaSsaPkcs1_2048_Sha384_Raw",
                   RsaSsaPkcs1(2048, RsaSsaPkcs1Parameters::HashType::kSha384,
                               RsaSsaPkcs1Parameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPkcs1_2048_Sha512_Tink",
                   RsaSsaPkcs1(2048, RsaSsaPkcs1Parameters::HashType::kSha512,
                               RsaSsaPkcs1Parameters::Variant::kTink)),
      MakeTestCase("RsaSsaPkcs1_3072_Sha256_Raw",
                   RsaSsaPkcs1(3072, RsaSsaPkcs1Parameters::HashType::kSha256,
                               RsaSsaPkcs1Parameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPkcs1_3072_Sha384_Tink",
                   RsaSsaPkcs1(3072, RsaSsaPkcs1Parameters::HashType::kSha384,
                               RsaSsaPkcs1Parameters::Variant::kTink)),
      MakeTestCase("RsaSsaPkcs1_3072_Sha512_Raw",
                   RsaSsaPkcs1(3072, RsaSsaPkcs1Parameters::HashType::kSha512,
                               RsaSsaPkcs1Parameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPkcs1_4096_Sha256_Tink",
                   RsaSsaPkcs1(4096, RsaSsaPkcs1Parameters::HashType::kSha256,
                               RsaSsaPkcs1Parameters::Variant::kTink)),
      MakeTestCase("RsaSsaPkcs1_4096_Sha384_Raw",
                   RsaSsaPkcs1(4096, RsaSsaPkcs1Parameters::HashType::kSha384,
                               RsaSsaPkcs1Parameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPkcs1_4096_Sha512_Tink",
                   RsaSsaPkcs1(4096, RsaSsaPkcs1Parameters::HashType::kSha512,
                               RsaSsaPkcs1Parameters::Variant::kTink)),
      // RSA-SSA-PSS: modulus size x hash. Salt length (0 or hash length) and
      // variant are spread across rows.
      MakeTestCase("RsaSsaPss_2048_Sha256_Salt32_Tink",
                   RsaSsaPss(2048, RsaSsaPssParameters::HashType::kSha256, 32,
                             RsaSsaPssParameters::Variant::kTink)),
      MakeTestCase("RsaSsaPss_2048_Sha384_Salt0_Raw",
                   RsaSsaPss(2048, RsaSsaPssParameters::HashType::kSha384, 0,
                             RsaSsaPssParameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPss_2048_Sha512_Salt64_Raw",
                   RsaSsaPss(2048, RsaSsaPssParameters::HashType::kSha512, 64,
                             RsaSsaPssParameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPss_3072_Sha256_Salt0_Raw",
                   RsaSsaPss(3072, RsaSsaPssParameters::HashType::kSha256, 0,
                             RsaSsaPssParameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPss_3072_Sha384_Salt48_Tink",
                   RsaSsaPss(3072, RsaSsaPssParameters::HashType::kSha384, 48,
                             RsaSsaPssParameters::Variant::kTink)),
      MakeTestCase("RsaSsaPss_3072_Sha512_Salt0_Tink",
                   RsaSsaPss(3072, RsaSsaPssParameters::HashType::kSha512, 0,
                             RsaSsaPssParameters::Variant::kTink)),
      MakeTestCase("RsaSsaPss_4096_Sha256_Salt32_Raw",
                   RsaSsaPss(4096, RsaSsaPssParameters::HashType::kSha256, 32,
                             RsaSsaPssParameters::Variant::kNoPrefix)),
      MakeTestCase("RsaSsaPss_4096_Sha384_Salt0_Tink",
                   RsaSsaPss(4096, RsaSsaPssParameters::HashType::kSha384, 0,
                             RsaSsaPssParameters::Variant::kTink)),
      MakeTestCase("RsaSsaPss_4096_Sha512_Salt64_Tink",
                   RsaSsaPss(4096, RsaSsaPssParameters::HashType::kSha512, 64,
                             RsaSsaPssParameters::Variant::kTink)),
  };
}

std::vector<Fips1402TestCase> DeniedAeadParameters() {
  return {
      // Key types which are not part of the FIPS configs.
      MakeTestCase(
          "AesGcmSiv_Key32_Tink",
          AesGcmSivParameters::Create(32, AesGcmSivParameters::Variant::kTink)),
      MakeTestCase("AesEax_Key16_Iv16_Raw",
                   AesEaxParameters::Builder()
                       .SetKeySizeInBytes(16)
                       .SetIvSizeInBytes(16)
                       .SetTagSizeInBytes(16)
                       .SetVariant(AesEaxParameters::Variant::kNoPrefix)
                       .Build()),
      MakeTestCase("XChaCha20Poly1305_Tink",
                   XChaCha20Poly1305Parameters::Create(
                       XChaCha20Poly1305Parameters::Variant::kTink)),
      // Salt sizes of the XAes256Gcm192BitNonce (12 bytes) and
      // XAes256Gcm160BitNonce (8 bytes) key templates.
      MakeTestCase("XAesGcm_Salt12_Tink",
                   XAesGcmParameters::Create(XAesGcmParameters::Variant::kTink,
                                             /*salt_size_bytes=*/12)),
      MakeTestCase(
          "XAesGcm_Salt8_Raw",
          XAesGcmParameters::Create(XAesGcmParameters::Variant::kNoPrefix,
                                    /*salt_size_bytes=*/8)),
  };
}

std::vector<Fips1402TestCase> DeniedMacParameters() {
  return {
      // Key types which are not part of the FIPS configs. The AES-CMAC key
      // manager only accepts 32 byte keys.
      MakeTestCase(
          "AesCmac_Key32_Tag16_Tink",
          AesCmacParameters::Create(32, 16, AesCmacParameters::Variant::kTink)),
  };
}

std::vector<Fips1402TestCase> DeniedPrfParameters() {
  return {
      // Key types which are not part of the FIPS configs. The AES-CMAC-PRF key
      // manager only accepts 32 byte keys.
      MakeTestCase("AesCmacPrf_Key32", AesCmacPrfParameters::Create(32)),
      MakeTestCase(
          "HkdfPrf_Key32_Sha256",
          HkdfPrfParameters::Create(32, HkdfPrfParameters::HashType::kSha256,
                                    /*salt=*/std::nullopt)),
  };
}

std::vector<Fips1402TestCase> DeniedSignatureParameters() {
  return {
      // There is no row for RSA moduli smaller than 2048 bits (e.g. 1024,
      // which FIPS 186-4 does allow): Tink rejects them in all modes, so
      // `RsaSsaPkcs1Parameters` and `RsaSsaPssParameters` cannot be built with
      // such sizes.
      //
      // Key types which are not part of the FIPS configs.
      MakeTestCase("Ed25519_Tink", Ed25519Parameters::Create(
                                       Ed25519Parameters::Variant::kTink)),
  };
}

absl::Status RegisterFips1402TestProtoSerializations() {
  for (absl::Status status : {
           // AEAD.
           RegisterAesGcmProtoSerialization(),
           RegisterAesCtrHmacAeadProtoSerialization(),
           RegisterAesGcmSivProtoSerialization(),
           RegisterAesEaxProtoSerialization(),
           RegisterXChaCha20Poly1305ProtoSerialization(),
           RegisterXAesGcmProtoSerialization(),
           // MAC.
           RegisterHmacProtoSerialization(),
           RegisterAesCmacProtoSerialization(),
           // PRF.
           RegisterHmacPrfProtoSerialization(),
           RegisterAesCmacPrfProtoSerialization(),
           RegisterHkdfPrfProtoSerialization(),
           // Signature.
           RegisterEcdsaProtoSerialization(),
           RegisterRsaSsaPkcs1ProtoSerialization(),
           RegisterRsaSsaPssProtoSerialization(),
           RegisterEd25519ProtoSerialization(),
       }) {
    if (!status.ok()) {
      return status;
    }
  }
  return absl::OkStatus();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
