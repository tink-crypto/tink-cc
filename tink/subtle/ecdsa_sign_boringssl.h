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

#ifndef TINK_SUBTLE_ECDSA_SIGN_BORINGSSL_H_
#define TINK_SUBTLE_ECDSA_SIGN_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// ECDSA signing using Boring SSL, generating signatures in DER-encoding.
class EcdsaSignBoringSsl : public PublicKeySign {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> New(
      const EcdsaPrivateKey& public_key);

  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> New(
      const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding) {
    return New(ec_key, hash_type, encoding, "", "");
  }

  // Computes the signature for 'data'.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

 private:
  static crypto::tink::util::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> New(
      const SubtleUtilBoringSSL::EcKey& ec_key, HashType hash_type,
      EcdsaSignatureEncoding encoding, absl::string_view output_prefix,
      absl::string_view message_suffix);

  explicit EcdsaSignBoringSsl(
      const EVP_MD* hash,
      std::unique_ptr<internal::EcdsaRawSignBoringSsl> raw_signer,
      absl::string_view output_prefix, absl::string_view message_suffix)
      : hash_(hash),
        raw_signer_(std::move(raw_signer)),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  util::StatusOr<std::string> SignWithoutPrefix(absl::string_view data) const;

  const EVP_MD* hash_;  // Owned by BoringSSL.
  std::unique_ptr<internal::EcdsaRawSignBoringSsl> raw_signer_;
  std::string output_prefix_;
  std::string message_suffix_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECDSA_SIGN_BORINGSSL_H_
