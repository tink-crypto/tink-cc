// Copyright 2021 Google LLC
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
#include "tink/internal/bn_util.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/bn.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status BignumToBinaryPadded(absl::Span<char> buffer,
                                  const BIGNUM *bignum) {
  if (bignum == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "BIGNUM is NULL");
  }
  if (BN_is_negative(bignum)) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Value must not be negative");
  }

  // BN_bn2binpad returns the length of the buffer on success and -1 on failure.
  int len = BN_bn2binpad(
      bignum, reinterpret_cast<unsigned char *>(buffer.data()), buffer.size());
  if (len == -1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Value too large to fit into the given buffer");
  }

  return absl::OkStatus();
}

absl::StatusOr<std::string> BignumToString(const BIGNUM *bn, size_t len) {
  if (bn == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "BIGNUM is NULL");
  }
  std::string buffer;
  subtle::ResizeStringUninitialized(&buffer, len);
  absl::Status res = BignumToBinaryPadded(absl::MakeSpan(&buffer[0], len), bn);
  if (!res.ok()) {
    return res;
  }
  return buffer;
}

absl::StatusOr<SecretData> BignumToSecretData(const BIGNUM *bn, size_t len) {
  if (bn == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "BIGNUM is NULL");
  }
  SecretBuffer secret_data(len);
  absl::Status res = internal::CallWithCoreDumpProtection([&] {
    return BignumToBinaryPadded(
        absl::MakeSpan(reinterpret_cast<char *>(secret_data.data()),
                       secret_data.size()),
        bn);
  });
  if (!res.ok()) {
    return res;
  }
  return util::internal::AsSecretData(std::move(secret_data));
}

absl::StatusOr<internal::SslUniquePtr<BIGNUM>> SecretDataToBignum(
    const SecretData &bigendian_bn_str) {
  internal::SslUniquePtr<BIGNUM> bn(internal::CallWithCoreDumpProtection([&] {
    return BN_bin2bn(
        reinterpret_cast<const unsigned char *>(bigendian_bn_str.data()),
        bigendian_bn_str.size(), /*ret=*/nullptr);
  }));
  if (bn.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "BIGNUM allocation failed");
  }
  return std::move(bn);
}

absl::StatusOr<internal::SslUniquePtr<BIGNUM>> StringToBignum(
    absl::string_view bigendian_bn_str) {
  internal::SslUniquePtr<BIGNUM> bn(internal::CallWithCoreDumpProtection([&] {
    return BN_bin2bn(
        reinterpret_cast<const unsigned char *>(bigendian_bn_str.data()),
        bigendian_bn_str.length(), /*ret=*/nullptr);
  }));
  if (bn.get() == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "BIGNUM allocation failed");
  }
  return std::move(bn);
}

int CompareBignumWithWord(const BIGNUM *bignum, BN_ULONG word) {
#ifdef OPENSSL_IS_BORINGSSL
  return BN_cmp_word(bignum, word);
#else
  internal::SslUniquePtr<BIGNUM> bn_word(BN_new());
  BN_set_word(bn_word.get(), word);
  return BN_cmp(bignum, bn_word.get());
#endif
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
