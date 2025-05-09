// Copyright 2020 Google LLC
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

#ifndef TINK_MAC_INTERNAL_STATEFUL_CMAC_BORINGSSL_H_
#define TINK_MAC_INTERNAL_STATEFUL_CMAC_BORINGSSL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/cmac.h"
#include "openssl/evp.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// A BoringSSL CMAC implementation of Stateful Mac interface.
class StatefulCmacBoringSsl : public StatefulMac {
 public:
  // Key must be 16 or 32 bytes, all other sizes will be rejected.
  static absl::StatusOr<std::unique_ptr<StatefulMac>> New(
      uint32_t tag_size, const SecretData& key_value);
  absl::Status Update(absl::string_view data) override;
  absl::StatusOr<SecretData> FinalizeAsSecretData() override;

 private:
  static constexpr size_t kSmallKeySize = 16;
  static constexpr size_t kBigKeySize = 32;
  static constexpr size_t kMaxTagSize = 16;

  StatefulCmacBoringSsl(uint32_t tag_size, internal::SslUniquePtr<CMAC_CTX> ctx)
      : cmac_context_(std::move(ctx)), tag_size_(tag_size) {}

  const internal::SslUniquePtr<CMAC_CTX> cmac_context_;
  const uint32_t tag_size_;
};

class StatefulCmacBoringSslFactory : public StatefulMacFactory {
 public:
  StatefulCmacBoringSslFactory(uint32_t tag_size, const SecretData& key_value);
  absl::StatusOr<std::unique_ptr<StatefulMac>> Create() const override;

 private:
  const uint32_t tag_size_;
  const SecretData key_value_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_STATEFUL_CMAC_BORINGSSL_H_
