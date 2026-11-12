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

#include "absl/memory/memory.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/internal/ecdsa_sign_boringssl.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// ECDSA signing using Boring SSL, generating signatures in DER-encoding.
class EcdsaSignBoringSsl : public PublicKeySign {
 public:
  static absl::StatusOr<std::unique_ptr<EcdsaSignBoringSsl>> New(
      const EcdsaPrivateKey& private_key) {
    ABSL_ASSIGN_OR_RETURN(std::unique_ptr<PublicKeySign> sign,
                          internal::NewEcdsaSignBoringSsl(private_key));
    return absl::WrapUnique(new EcdsaSignBoringSsl(std::move(sign)));
  }

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override {
    return sign_->Sign(data);
  }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  ~EcdsaSignBoringSsl() override = default;

 protected:
  EcdsaSignBoringSsl() = default;

 private:
  explicit EcdsaSignBoringSsl(std::unique_ptr<PublicKeySign> sign)
      : sign_(std::move(sign)) {}

  std::unique_ptr<PublicKeySign> sign_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECDSA_SIGN_BORINGSSL_H_
