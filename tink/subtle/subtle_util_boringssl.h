// Copyright 2017 Google LLC
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
///////////////////////////////////////////////////////////////////////////////

#ifndef TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
#define TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class SubtleUtilBoringSSL {
 public:
  using EcKey ABSL_DEPRECATED("Use of this type is discouraged outside Tink.") =
      internal::EcKey;
  struct ABSL_DEPRECATED("Use of this type is discouraged outside Tink.")
      Ed25519Key {
    std::string public_key;
    std::string private_key;
  };
  using RsaPublicKey ABSL_DEPRECATED(
      "Use of this type is discouraged outside Tink.") = internal::RsaPublicKey;
  using RsaSsaPssParams ABSL_DEPRECATED(
      "Use of this type is discouraged outside Tink.") =
      internal::RsaSsaPssParams;
  using RsaSsaPkcs1Params ABSL_DEPRECATED(
      "Use of this type is discouraged outside Tink.") =
      internal::RsaSsaPkcs1Params;
  using RsaPrivateKey ABSL_DEPRECATED(
      "Use of this type is discouraged outside Tink.") =
      internal::RsaPrivateKey;

  // Returns BoringSSL's BIGNUM constructed from bigendian string
  // representation.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<internal::SslUniquePtr<BIGNUM>> str2bn(
      absl::string_view s) {
    return internal::StringToBignum(s);
  }

  // Returns a SecretData of size 'len' that holds BIGNUM 'bn'.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<std::string> bn2str(const BIGNUM *bn,
                                                   size_t len) {
    return internal::BignumToString(bn, len);
  }

  // Returns a string of size 'len' that holds BIGNUM 'bn'.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<util::SecretData> BignumToSecretData(
      const BIGNUM *bn, size_t len) {
    return internal::BignumToSecretData(bn, len);
  }

  // Returns BoringSSL error strings accumulated in the error queue,
  // thus emptying the queue.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline std::string GetErrors() { return internal::GetSslErrors(); }

  // Returns BoringSSL's EC_GROUP constructed from the curve type.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<EC_GROUP *> GetEcGroup(
      EllipticCurveType curve_type) {
    absl::StatusOr<internal::SslUniquePtr<EC_GROUP>> ec_group =
        internal::EcGroupFromCurveType(curve_type);
    if (!ec_group.ok()) {
      return ec_group.status();
    }
    return ec_group->release();
  }

  // Returns the curve type associated with the EC_GROUP
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<EllipticCurveType> GetCurve(
      const EC_GROUP *group) {
    return internal::CurveTypeFromEcGroup(group);
  }

  // Returns BoringSSL's EC_POINT constructed from the curve type, big-endian
  // representation of public key's x-coordinate and y-coordinate.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<EC_POINT *> GetEcPoint(EllipticCurveType curve,
                                                      absl::string_view pubx,
                                                      absl::string_view puby) {
    absl::StatusOr<internal::SslUniquePtr<EC_POINT>> ec_point =
        internal::GetEcPoint(curve, pubx, puby);
    if (!ec_point.ok()) {
      return ec_point.status();
    }
    return ec_point->release();
  }

  // Returns a new EC key for the specified curve.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<EcKey> GetNewEcKey(
      EllipticCurveType curve_type) {
    return internal::NewEcKey(curve_type);
  }

  // Returns a new EC key for the specified curve derived from a seed.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<EcKey> GetNewEcKeyFromSeed(
      EllipticCurveType curve_type, const util::SecretData &secret_seed) {
    return internal::NewEcKey(curve_type, secret_seed);
  }

  // Returns a new ED25519 key.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline std::unique_ptr<Ed25519Key> GetNewEd25519Key() {
    absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
        internal::NewEd25519Key();
    if (!key.ok()) {
      return nullptr;
    }
    Ed25519Key subtle_key;
    subtle_key.public_key = (*key)->public_key;
    subtle_key.private_key =
        std::string(util::SecretDataAsStringView((*key)->private_key));
    return std::make_unique<Ed25519Key>(std::move(subtle_key));
  }

  // Returns a new ED25519 key generated from a 32-byte secret seed.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline std::unique_ptr<Ed25519Key> GetNewEd25519KeyFromSeed(
      const util::SecretData &secret_seed) {
    absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key =
        internal::NewEd25519Key(secret_seed);
    if (!key.ok()) {
      return nullptr;
    }
    Ed25519Key subtle_key;
    subtle_key.public_key = (*key)->public_key;
    subtle_key.private_key =
        std::string(util::SecretDataAsStringView((*key)->private_key));
    return std::make_unique<Ed25519Key>(std::move(subtle_key));
  }

  // Returns BoringSSL's EC_POINT constructed from curve type, point format and
  // encoded public key's point. The uncompressed point is encoded as
  // 0x04 || x || y where x, y are curve_size_in_bytes big-endian byte array.
  // The compressed point is encoded as 1-byte || x where x is
  // curve_size_in_bytes big-endian byte array and if the least significant bit
  // of y is 1, the 1st byte is 0x03, otherwise it's 0x02.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<internal::SslUniquePtr<EC_POINT>> EcPointDecode(
      EllipticCurveType curve, EcPointFormat format,
      absl::string_view encoded) {
    return internal::EcPointDecode(curve, format, encoded);
  }

  // Returns the encoded public key based on curve type, point format and
  // BoringSSL's EC_POINT public key point. The uncompressed point is encoded as
  // 0x04 || x || y where x, y are curve_size_in_bytes big-endian byte array.
  // The compressed point is encoded as 1-byte || x where x is
  // curve_size_in_bytes big-endian byte array and if the least significant bit
  // of y is 1, the 1st byte is 0x03, otherwise it's 0x02.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<std::string> EcPointEncode(
      EllipticCurveType curve, EcPointFormat format, const EC_POINT *point) {
    return internal::EcPointEncode(curve, format, point);
  }

  // Returns the ECDH's shared secret based on our private key and peer's public
  // key. Returns error if the public key is not on private key's curve.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<util::SecretData> ComputeEcdhSharedSecret(
      EllipticCurveType curve, const BIGNUM *priv_key,
      const EC_POINT *pub_key) {
    return internal::ComputeEcdhSharedSecret(curve, priv_key, pub_key);
  }

  // Transforms ECDSA IEEE_P1363 signature encoding to DER encoding.
  //
  // The IEEE_P1363 signature's format is r || s, where r and s are zero-padded
  // and have the same size in bytes as the order of the curve. For example, for
  // NIST P-256 curve, r and s are zero-padded to 32 bytes.
  //
  // The DER signature is encoded using ASN.1
  // (https://tools.ietf.org/html/rfc5480#appendix-A):
  //   ECDSA-Sig-Value :: = SEQUENCE { r INTEGER, s INTEGER }.
  // In particular, the encoding is:
  //   0x30 || totalLength || 0x02 || r's length || r || 0x02 || s's length || s
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<std::string> EcSignatureIeeeToDer(
      const EC_GROUP *group, absl::string_view ieee_sig) {
    return internal::EcSignatureIeeeToDer(group, ieee_sig);
  }

  // Returns an EVP structure for a hash function.
  // The EVP_MD instances are sigletons owned by BoringSSL.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<const EVP_MD *> EvpHash(HashType hash_type) {
    return internal::EvpHashFromHashType(hash_type);
  }

  // Validates whether 'sig_hash' is safe to use for digital signature.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status ValidateSignatureHash(subtle::HashType sig_hash) {
    return internal::IsHashTypeSafeForSignature(sig_hash);
  }

  // Return an empty string if str.data() is nullptr; otherwise return str.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::string_view EnsureNonNull(absl::string_view str) {
    return internal::EnsureStringNonNull(str);
  }

  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status ValidateRsaModulusSize(size_t modulus_size) {
    return internal::ValidateRsaModulusSize(modulus_size);
  }

  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status ValidateRsaPublicExponent(
      absl::string_view exponent) {
    return internal::ValidateRsaPublicExponent(exponent);
  }

  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status GetNewRsaKeyPair(int modulus_size_in_bits,
                                              const BIGNUM *e,
                                              RsaPrivateKey *private_key,
                                              RsaPublicKey *public_key) {
    return internal::NewRsaKeyPair(modulus_size_in_bits, e, private_key,
                                   public_key);
  }

  // Copies n, e and d into the RSA key.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status CopyKey(const RsaPrivateKey &key, RSA *rsa) {
    return internal::GetRsaModAndExponents(key, rsa);
  }

  // Copies the prime factors (p, q) into the RSA key.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status CopyPrimeFactors(const RsaPrivateKey &key,
                                              RSA *rsa) {
    return internal::GetRsaPrimeFactors(key, rsa);
  }

  // Copies the CRT params and dp, dq into the RSA key.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::Status CopyCrtParams(const RsaPrivateKey &key, RSA *rsa) {
    return internal::GetRsaCrtParams(key, rsa);
  }

  // Creates a BoringSSL RSA key from an RsaPrivateKey.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPrivateKey(const RsaPrivateKey &key) {
    return internal::RsaPrivateKeyToRsa(key);
  }

  // Creates a BoringSSL RSA key from an RsaPublicKey.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline absl::StatusOr<internal::SslUniquePtr<RSA>>
  BoringSslRsaFromRsaPublicKey(const RsaPublicKey &key) {
    return internal::RsaPublicKeyToRsa(key);
  }

  // Returns BoringSSL's AES CTR EVP_CIPHER for the key size.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline const EVP_CIPHER *GetAesCtrCipherForKeySize(
      uint32_t size_in_bytes) {
    absl::StatusOr<const EVP_CIPHER *> res =
        internal::GetAesCtrCipherForKeySize(size_in_bytes);
    if (!res.ok()) {
      return nullptr;
    }
    return *res;
  }

  // Returns BoringSSL's AES GCM EVP_CIPHER for the key size.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline const EVP_CIPHER *GetAesGcmCipherForKeySize(
      uint32_t size_in_bytes) {
    absl::StatusOr<const EVP_CIPHER *> res =
        internal::GetAesGcmCipherForKeySize(size_in_bytes);
    if (!res.ok()) {
      return nullptr;
    }
    return *res;
  }

#ifdef OPENSSL_IS_BORINGSSL
  // Returns BoringSSL's AES GCM EVP_AEAD for the key size.
  ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
  static inline const EVP_AEAD *GetAesGcmAeadForKeySize(
      uint32_t size_in_bytes) {
    absl::StatusOr<const EVP_AEAD *> res =
        internal::GetAesGcmAeadForKeySize(size_in_bytes);
    if (!res.ok()) {
      return nullptr;
    }
    return *res;
  }
#endif
};

namespace boringssl {

// Computes hash of 'input' using the hash function 'hasher'.
ABSL_DEPRECATED("Use of this function is discouraged outside Tink.")
inline absl::StatusOr<std::vector<uint8_t>> ComputeHash(absl::string_view input,
                                                        const EVP_MD &hasher) {
  absl::StatusOr<std::string> res = internal::ComputeHash(input, hasher);
  if (!res.ok()) {
    return res.status();
  }
  return std::vector<uint8_t>(res->begin(), res->end());
}

}  // namespace boringssl
}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
