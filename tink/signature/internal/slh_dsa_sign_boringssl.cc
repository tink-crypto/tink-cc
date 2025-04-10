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

#include "tink/signature/internal/slh_dsa_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/slhdsa.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/slh_dsa_private_key.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

class SlhDsaSignBoringSsl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  explicit SlhDsaSignBoringSsl(const SlhDsaPrivateKey &private_key)
      : private_key_(private_key) {}

  ~SlhDsaSignBoringSsl() override = default;

  // Computes the signature for 'data'.
  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

 private:
  SlhDsaPrivateKey private_key_;
};

absl::StatusOr<std::string> SlhDsaSignBoringSsl::Sign(
    absl::string_view data) const {
  // The signature will be prepended with the output prefix for TINK keys.
  std::string signature(private_key_.GetOutputPrefix());
  size_t signature_buffer_size =
      SLHDSA_SHA2_128S_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size();
  subtle::ResizeStringUninitialized(&signature, signature_buffer_size);

  internal::CallWithCoreDumpProtection([&]() {
    internal::ScopedAssumeRegionCoreDumpSafe scope(&signature[0],
                                                   signature_buffer_size);
    SLHDSA_SHA2_128S_sign(
        reinterpret_cast<uint8_t *>(&signature[0] +
                                    private_key_.GetOutputPrefix().size()),
        private_key_.GetPrivateKeyBytes(GetPartialKeyAccess())
            .Get(InsecureSecretKeyAccess::Get())
            .data(),
        reinterpret_cast<const uint8_t *>(data.data()), data.size(),
        /* context = */ nullptr, /* context_len = */ 0);
    internal::DfsanClearLabel(&signature[0], signature_buffer_size);
  });

  return signature;
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewSlhDsaSignBoringSsl(
    const SlhDsaPrivateKey &private_key) {
  auto status = internal::CheckFipsCompatibility<SlhDsaSignBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  return {std::make_unique<SlhDsaSignBoringSsl>(std::move(private_key))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
