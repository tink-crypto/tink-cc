// Copyright 2018 Google Inc.
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

#ifndef TINK_AEAD_AEAD_KEY_TEMPLATES_H_
#define TINK_AEAD_AEAD_KEY_TEMPLATES_H_

#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for Aead key types. One can use these templates
// to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single AesGcmKey, one can do:
//
//   auto status = AeadConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result =
//       KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class AeadKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of AesEaxKey
  // with the following parameters:
  //   - key size: 16 bytes
  //   - IV size: 16 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes128Eax();

  // Returns a KeyTemplate that generates new instances of AesEaxKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - IV size: 16 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes256Eax();

  // Returns a KeyTemplate that generates new instances of AesGcmKey
  // with the following parameters:
  //   - key size: 16 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes128Gcm();

  // Returns a KeyTemplate that generates new instances of AesGcmKey
  // with the following parameters:
  //   - key size: 16 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate& Aes128GcmNoPrefix();

  // Returns a KeyTemplate that generates new instances of AesGcmKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes256Gcm();

  // Returns a KeyTemplate that generates new instances of AesGcmKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate& Aes256GcmNoPrefix();

  // Returns a KeyTemplate that generates new instances of AesGcmSivKey
  // with the following parameters:
  //   - key size: 16 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes128GcmSiv();

  // Returns a KeyTemplate that generates new instances of AesGcmSivKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes256GcmSiv();

  // Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
  // with the following parameters:
  //   - AES key size: 16 bytes
  //   - AES IV size: 16 bytes
  //   - HMAC key size: 32 bytes
  //   - HMAC tag size: 16 bytes
  //   - HMAC hash function: SHA256
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes128CtrHmacSha256();

  // Returns a KeyTemplate that generates new instances of AesCtrHmacAeadKey
  // with the following parameters:
  //   - AES key size: 32 bytes
  //   - AES IV size: 16 bytes
  //   - HMAC key size: 32 bytes
  //   - HMAC tag size: 32 bytes
  //   - HMAC hash function: SHA256
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes256CtrHmacSha256();

  // Returns a KeyTemplate that generates new instances of XChaCha20Poly1305Key
  // with the following parameters:
  //   - XChacha20 key size: 32 bytes
  //   - IV size: 24 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& XChaCha20Poly1305();

  // Returns a KeyTemplate that generates new instances of XAesGcmKey
  // This follows the algorithm defined in the XAES-256-GCM specification:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md.
  // Has the following parameters:
  //   - key size: 32 bytes
  //   - nonce size: 24 bytes (12 bytes of salt, 12 bytes of AES-GCM IV)
  //   - salt size: 12 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& XAes256Gcm192BitNonce();

  // Returns a KeyTemplate that generates new instances of XAesGcmKey
  // This follows the algorithm defined in the XAES-256-GCM specification:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md.
  // Has the following parameters:
  //   - key size: 32 bytes
  //   - nonce size: 24 bytes (12 bytes of salt, 12 bytes of (AES-GCM IV)
  //   - salt size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate&
  XAes256Gcm192BitNonceNoPrefix();

  // Returns a KeyTemplate that generates new instances of XAesGcmKey
  // This follows the algorithm defined in the XAES-256-GCM specification:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md. Except that the
  // nonce size is 160 bits instead of 192 bits. The remaining 4 bytes are
  // padded with zeros. Has the following parameters:
  //   - key size: 32 bytes
  //   - nonce size: 20 bytes (8 bytes of salt, 12 bytes of AES-GCM IV)
  //   - salt size: 8 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& XAes256Gcm160BitNonce();

  // Returns a KeyTemplate that generates new instances of XAesGcmKey
  // This follows the algorithm defined in the XAES-256-GCM specification:
  // https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md. Except that the
  // nonce size is 160 bits instead of 192 bits. The remaining 4 bytes are
  // padded with zeros. Has the following parameters:
  //   - key size: 32 bytes
  //   - nonce size: 20 bytes (8 bytes of salt, 12 bytes of AES-GCM IV)
  //   - salt size: 8 bytes
  //   - IV size: 12 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: RAW
  static const google::crypto::tink::KeyTemplate&
  XAes256Gcm160BitNonceNoPrefix();

  ABSL_DEPRECATE_AND_INLINE()
  static const google::crypto::tink::KeyTemplate& XAes256Gcm8ByteSalt() {
    return XAes256Gcm160BitNonce();
  }

  ABSL_DEPRECATE_AND_INLINE()
  static const google::crypto::tink::KeyTemplate&
  XAes256Gcm8ByteSaltNoPrefix() {
    return XAes256Gcm160BitNonceNoPrefix();
  }

  // Returns a KeyTemplate that generates new instances of KmsEnvelopeAeadKey
  // with the following parameters:
  //   - KEK is pointing to kek_uri
  //   - DEK template is dek_template
  //   - OutputPrefixType: RAW. This uses RAW output prefix to make it
  //   compatible with the remote KMS' encrypt/decrypt operations. Unlike other
  //   templates, when you generate new keys with this template, Tink does not
  //   generate new key material, but only creates a reference to the remote
  //   KEK.
  ABSL_DEPRECATED(
      "AeadKeyTemplates::KmsEnvelopeAead is deprecated. Instead, get the remote"
      "AEAD with KmsClient::GetAead, and then create the envelope AEAD using "
      "KmsEnvelopeAead::New without registering the KmsClient object.")
  static google::crypto::tink::KeyTemplate KmsEnvelopeAead(
      absl::string_view kek_uri,
      const google::crypto::tink::KeyTemplate& dek_template);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AEAD_KEY_TEMPLATES_H_
