// Copyright 2024 Google LLC
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

#ifndef TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_
#define TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Public Key Signing using the SLH-DSA-SHA2-128s implementation from BoringSSL.
class SlhDsaSignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  static crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>> New(
      const SlhDsaPrivateKey& private_key);

  ~SlhDsaSignBoringSsl() override = default;

  // Computes the signature for 'data'.
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

 private:
  explicit SlhDsaSignBoringSsl(const SlhDsaPrivateKey& private_key)
      : private_key_(private_key) {}

  SlhDsaPrivateKey private_key_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_PQCRYPTO_SIGNATURE_INTERNAL_SLH_DSA_SIGN_BORINGSSL_H_
