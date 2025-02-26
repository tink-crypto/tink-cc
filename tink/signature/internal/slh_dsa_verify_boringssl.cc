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

#include "tink/signature/internal/slh_dsa_verify_boringssl.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/slhdsa.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/slh_dsa_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

// Public Key Verification using SLH-DSA-SHA2-128s implementation from
// BoringSSL.
class SlhDsaVerifyBoringSsl : public PublicKeyVerify {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  explicit SlhDsaVerifyBoringSsl(const SlhDsaPublicKey &public_key)
      : public_key_(public_key) {}

  ~SlhDsaVerifyBoringSsl() override = default;

  // Verifies that 'signature' is a digital signature for 'data'.
  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    if (signature.size() < SLHDSA_SHA2_128S_SIGNATURE_BYTES +
                               public_key_.GetOutputPrefix().size()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Verification failed: invalid signature length");
    }

    if (!absl::StartsWith(signature, public_key_.GetOutputPrefix())) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Verification failed: invalid output prefix");
    }

    if (1 !=
        SLHDSA_SHA2_128S_verify(
            reinterpret_cast<const uint8_t *>(
                signature.data() + public_key_.GetOutputPrefix().size()),
            SLHDSA_SHA2_128S_SIGNATURE_BYTES,
            reinterpret_cast<const uint8_t *>(
                public_key_.GetPublicKeyBytes(GetPartialKeyAccess()).data()),
            reinterpret_cast<const uint8_t *>(data.data()), data.size(),
            /* context = */ nullptr, /* context_len = */ 0)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Signature is not valid");
    }

    return absl::OkStatus();
  }

 private:
  SlhDsaPublicKey public_key_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> NewSlhDsaVerifyBoringSsl(
    const SlhDsaPublicKey &public_key) {
  auto status = internal::CheckFipsCompatibility<SlhDsaVerifyBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  return {std::make_unique<SlhDsaVerifyBoringSsl>(std::move(public_key))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
