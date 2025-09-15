// Copyright 2025 Google LLC
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

#include "tink/internal/xwing_util.h"

#include <cstddef>
#include <utility>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "openssl/bytestring.h"
#include "openssl/xwing.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<XWingKey> NewXWingKey() {
  XWingKey key;
  SecretBuffer xwing_priv_key_buffer(kXWingKeyPrivKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    XWING_private_key xwing_private_key;
    if (!XWING_generate_key(key.public_key.data(), &xwing_private_key)) {
      return absl::Status(absl::StatusCode::kInternal,
                          "XWING_generate_key failed");
    }
    CBB cbb;
    size_t size;
    if (!CBB_init_fixed(&cbb, xwing_priv_key_buffer.data(),
                        kXWingKeyPrivKeySize) ||
        !XWING_marshal_private_key(&cbb, &xwing_private_key) ||
        !CBB_finish(&cbb, /*out_data=*/nullptr, &size) ||
        size != kXWingKeyPrivKeySize) {
      return absl::Status(absl::StatusCode::kInternal,
                          "XWING_marshal_private_key failed");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key =
      util::internal::AsSecretData(std::move(xwing_priv_key_buffer));
  return key;
}

absl::StatusOr<XWingKey> XWingKeyFromPrivateKey(const SecretData& private_key) {
  if (private_key.size() != kXWingKeyPrivKeySize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid length for private key");
  }
  XWingKey key;
  SecretBuffer xwing_priv_key_buffer(kXWingKeyPrivKeySize);
  absl::Status status = CallWithCoreDumpProtection([&]() {
    XWING_private_key xwing_private_key;
    CBS cbs;
    CBS_init(&cbs, private_key.data(), private_key.size());
    if (!XWING_parse_private_key(&xwing_private_key, &cbs) ||
        CBS_len(&cbs) != 0) {
      return absl::Status(absl::StatusCode::kInternal,
                          "XWING_parse_private_key failed");
    }
    if (!XWING_public_from_private(key.public_key.data(), &xwing_private_key)) {
      return absl::Status(absl::StatusCode::kInternal,
                          "XWING_public_from_private failed");
    }
    CBB cbb;
    size_t size;
    if (!CBB_init_fixed(&cbb, xwing_priv_key_buffer.data(),
                        kXWingKeyPrivKeySize) ||
        !XWING_marshal_private_key(&cbb, &xwing_private_key) ||
        !CBB_finish(&cbb, /*out_data=*/nullptr, &size) ||
        size != kXWingKeyPrivKeySize) {
      return absl::Status(absl::StatusCode::kInternal,
                          "XWING_marshal_private_key failed");
    }
    return absl::OkStatus();
  });
  if (!status.ok()) {
    return status;
  }
  key.private_key =
      util::internal::AsSecretData(std::move(xwing_priv_key_buffer));
  return key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
