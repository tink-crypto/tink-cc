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

#ifndef TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
#define TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/ecdsa_verify_boringssl.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {

// ECDSA verification using Boring SSL, accepting signatures in DER-encoding.
class EcdsaVerifyBoringSsl : public PublicKeyVerify {
 public:
  static absl::StatusOr<std::unique_ptr<EcdsaVerifyBoringSsl>> New(
      const EcdsaPublicKey& public_key) {
    ABSL_ASSIGN_OR_RETURN(std::unique_ptr<PublicKeyVerify> verify,
                          internal::NewEcdsaVerifyBoringSsl(public_key));
    return absl::WrapUnique(new EcdsaVerifyBoringSsl(std::move(verify)));
  }

  // Verifies that 'signature' is a digital signature for 'data'.
  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    return verify_->Verify(signature, data);
  }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  ~EcdsaVerifyBoringSsl() override = default;

 protected:
  EcdsaVerifyBoringSsl() = default;

 private:
  explicit EcdsaVerifyBoringSsl(std::unique_ptr<PublicKeyVerify> verify)
      : verify_(std::move(verify)) {}

  std::unique_ptr<PublicKeyVerify> verify_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_ECDSA_VERIFY_BORINGSSL_H_
