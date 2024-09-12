// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/internal/base_x_aes_gcm.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/cmac.h"
#include "openssl/evp.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/partial_key_access.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::CallWithCoreDumpProtection;
using ::crypto::tink::util::SecretData;

constexpr int kAesBlockSize = 16;
constexpr int kAesKeySize = 32;
constexpr int kAesGcmIvSize = 12;
constexpr int kMinSaltSize = 8;
constexpr int kMaxSaltSize = 12;
constexpr int kTagSize = kAesBlockSize;
constexpr int kSaltOffset = 4;

absl::StatusOr<SslUniquePtr<CMAC_CTX>> CloneCmacContext(
    const CMAC_CTX& cmac_ctx) {
  SslUniquePtr<CMAC_CTX> copy_ctx(CMAC_CTX_new());
  if (copy_ctx == nullptr) {
    return absl::InternalError("failed CMAC_CTX_new");
  }
  if (CMAC_CTX_copy(copy_ctx.get(), &cmac_ctx) != 1) {
    return absl::InternalError("failed CMAC_CTX_copy");
  }
  return std::move(copy_ctx);
}

absl::Status SingleShotCmac(CMAC_CTX& cmac_ctx, uint8_t* data, size_t size,
                            uint8_t* output) {
  if (CMAC_Update(&cmac_ctx, data, size) != 1) {
    return absl::InternalError("failed CMAC_Update");
  }
  size_t out_len = 0;
  if (CMAC_Final(&cmac_ctx, output, &out_len) != 1) {
    return absl::InternalError("failed CMAC_Final");
  }
  if (out_len != kAesBlockSize) {
    return absl::InternalError("CMAC_Final returned unexpected output length");
  }
  return absl::OkStatus();
}

// KDF in CTR mode, as specified in: SP-800 - 108r1, using AES-CMAC as
// the underlying PRF.
absl::StatusOr<SecretData> DerivePerMessageKeyImpl(const CMAC_CTX& cmac_ctx,
                                                   absl::string_view salt) {
  uint8_t derivation_block_1[kAesBlockSize] = {
      0, 1, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  uint8_t derivation_block_2[kAesBlockSize] = {
      0, 2, 'X', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  if (salt.size() > kMaxSaltSize) {
    return absl::InvalidArgumentError(
        absl::StrFormat("salt size must be at most %d bytes", kMaxSaltSize));
  }
  if (salt.size() < kMinSaltSize) {
    return absl::InvalidArgumentError(
        absl::StrFormat("salt size must be at least %d bytes", kMinSaltSize));
  }

  std::memcpy(derivation_block_1 + kSaltOffset, salt.data(), salt.size());
  std::memcpy(derivation_block_2 + kSaltOffset, salt.data(), salt.size());

  SecretData derived_key(kAesKeySize);
  absl::StatusOr<SslUniquePtr<CMAC_CTX>> local_cmac_ctx =
      CloneCmacContext(cmac_ctx);
  if (!local_cmac_ctx.ok()) {
    return local_cmac_ctx.status();
  }
  absl::Status status = SingleShotCmac(**local_cmac_ctx, derivation_block_1,
                                       kAesBlockSize, derived_key.data());
  if (!status.ok()) {
    return status;
  }
#ifdef OPENSSL_IS_BORINGSSL
  if (CMAC_Reset((*local_cmac_ctx).get()) != 1) {
    return absl::InternalError("failed CMAC_Reset");
  }
#else
  if (CMAC_CTX_copy((*local_cmac_ctx).get(), &cmac_ctx) != 1) {
    return absl::InternalError("failed CMAC_CTX_copy");
  }
#endif
  status = SingleShotCmac(**local_cmac_ctx, derivation_block_2, kAesBlockSize,
                          derived_key.data() + kAesBlockSize);
  if (!status.ok()) {
    return status;
  }
  return derived_key;
}

absl::Status InitializeCmacContext(SslUniquePtr<CMAC_CTX>& cmac_ctx,
                                   const SecretData& key_value) {
  if (CMAC_Init(cmac_ctx.get(), key_value.data(), kAesKeySize,
                EVP_aes_256_cbc(),
                /*engine=*/nullptr) != 1) {
    return absl::InternalError("failed CMAC_Init");
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<BaseXAesGcm> BaseXAesGcm::New(XAesGcmKey key) {
  // XAesGcmKey validates key size and parameters.
  SslUniquePtr<CMAC_CTX> cmac_ctx(CMAC_CTX_new());
  if (cmac_ctx == nullptr) {
    return absl::InternalError("failed CMAC_CTX_new");
  }
  absl::Status status = CallWithCoreDumpProtection([&] {
    return InitializeCmacContext(cmac_ctx,
                                 key.GetKeyBytes(GetPartialKeyAccess())
                                     .Get(InsecureSecretKeyAccess::Get()));
  });
  if (!status.ok()) {
    return status;
  }
  return BaseXAesGcm(std::move(cmac_ctx), key.GetParameters().SaltSizeBytes());
}

int BaseXAesGcm::min_ct_size() const {
  return salt_size_ + kAesGcmIvSize + kTagSize;
}


absl::StatusOr<util::SecretData> BaseXAesGcm::DerivePerMessageKey(
    absl::string_view salt) const {
  return CallWithCoreDumpProtection(
      [&] { return DerivePerMessageKeyImpl(*cmac_ctx_, salt); });
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
