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

#include "tink/mac/internal/stateful_cmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/util/secret_data.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<std::unique_ptr<StatefulMac>> StatefulCmacBoringSsl::New(
    uint32_t tag_size, const SecretData& key_value) {
  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCbcCipherForKeySize(key_value.size());
  if (!cipher.ok()) {
    return cipher.status();
  }
  if (tag_size > kMaxTagSize) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid tag size");
  }

  // Create and initialize the CMAC context
  internal::SslUniquePtr<CMAC_CTX> ctx(CMAC_CTX_new());

  // Initialize the CMAC
  if (!CallWithCoreDumpProtection([&]() {
        return CMAC_Init(ctx.get(), key_value.data(), key_value.size(), *cipher,
                         nullptr /* engine */);
      })) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "CMAC initialization failed");
  }

  return {
      absl::WrapUnique(new StatefulCmacBoringSsl(tag_size, std::move(ctx)))};
}

absl::Status StatefulCmacBoringSsl::Update(absl::string_view data) {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  int update_result = CallWithCoreDumpProtection([&]() {
    return CMAC_Update(cmac_context_.get(),
                       reinterpret_cast<const uint8_t*>(data.data()),
                       data.size());
  });
  if (!update_result) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Inputs to CMAC Update invalid");
  }
  return absl::OkStatus();
}

absl::StatusOr<SecretData> StatefulCmacBoringSsl::FinalizeAsSecretData() {
  SecretBuffer buf(EVP_MAX_MD_SIZE);
  size_t out_len;

  if (!CallWithCoreDumpProtection([&]() {
        return CMAC_Final(cmac_context_.get(), buf.data(), &out_len);
      })) {
    return absl::Status(absl::StatusCode::kInternal,
                        "CMAC finalization failed");
  }
  return util::internal::AsSecretData(std::move(buf).substr(0, tag_size_));
}

StatefulCmacBoringSslFactory::StatefulCmacBoringSslFactory(
    uint32_t tag_size, const SecretData& key_value)
    : tag_size_(tag_size), key_value_(key_value) {}

absl::StatusOr<std::unique_ptr<StatefulMac>>
StatefulCmacBoringSslFactory::Create() const {
  return StatefulCmacBoringSsl::New(tag_size_, key_value_);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
