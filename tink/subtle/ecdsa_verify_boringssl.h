// Copyright 2017 Google Inc.
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

#ifndef TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// ECDSA verification using Boring SSL, accepting signatures in DER-encoding.
class EcdsaVerifyBoringSsl : public PublicKeyVerify {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeyVerify>> New(
      const EcdsaPublicKey& public_key);

  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding) {
    return New(ec_key, hash_type, encoding, "", "");
  }

  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(internal::SslUniquePtr<EC_KEY> ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding) {
    return New(std::move(ec_key), hash_type, encoding, "", "");
  }

  // Verifies that 'signature' is a digital signature for 'data'.
  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
      absl::string_view message_suffix);
  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>>
  New(internal::SslUniquePtr<EC_KEY> ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
      absl::string_view message_suffix);

  EcdsaVerifyBoringSsl(internal::SslUniquePtr<EC_KEY> key, const EVP_MD* hash,
                       EcdsaSignatureEncoding encoding,
                       absl::string_view output_prefix,
                       absl::string_view message_suffix)
      : key_(std::move(key)),
        hash_(hash),
        encoding_(encoding),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::Status VerifyWithoutPrefix(absl::string_view signature,
                                   absl::string_view data) const;

  internal::SslUniquePtr<EC_KEY> key_;
  const EVP_MD* hash_;  // Owned by BoringSSL.
  EcdsaSignatureEncoding encoding_;
  const std::string output_prefix_;
  const std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
