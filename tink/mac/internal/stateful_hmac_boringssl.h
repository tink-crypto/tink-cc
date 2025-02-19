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

#ifndef TINK_MAC_INTERNAL_STATEFUL_HMAC_BORINGSSL_H_
#define TINK_MAC_INTERNAL_STATEFUL_HMAC_BORINGSSL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// A BoringSSL HMAC implementation of Stateful Mac interface.
class StatefulHmacBoringSsl : public StatefulMac {
 public:
  static util::StatusOr<std::unique_ptr<StatefulMac>> New(
      subtle::HashType hash_type, uint32_t tag_size,
      const util::SecretData& key_value);
  absl::Status Update(absl::string_view data) override;
  util::StatusOr<util::SecretData> FinalizeAsSecretData() override;

 private:
  // Minimum HMAC key size in bytes.
  static constexpr size_t kMinKeySize = 16;

  StatefulHmacBoringSsl(uint32_t tag_size, internal::SslUniquePtr<HMAC_CTX> ctx)
      : hmac_context_(std::move(ctx)), tag_size_(tag_size) {}

  const internal::SslUniquePtr<HMAC_CTX> hmac_context_;
  const uint32_t tag_size_;
};

class StatefulHmacBoringSslFactory : public StatefulMacFactory {
 public:
  StatefulHmacBoringSslFactory(subtle::HashType hash_type, uint32_t tag_size,
                               const util::SecretData& key_value);
  util::StatusOr<std::unique_ptr<StatefulMac>> Create() const override;

 private:
  const subtle::HashType hash_type_;
  const uint32_t tag_size_;
  const util::SecretData key_value_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_STATEFUL_HMAC_BORINGSSL_H_
