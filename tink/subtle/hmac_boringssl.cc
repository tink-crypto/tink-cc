// Copyright 2017 Google Inc.
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

#include "tink/subtle/hmac_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

absl::StatusOr<std::unique_ptr<Mac>> HmacBoringSsl::New(HashType hash_type,
                                                        uint32_t tag_size,
                                                        SecretData key) {
  auto status = internal::CheckFipsCompatibility<HmacBoringSsl>();
  if (!status.ok()) return status;

  absl::StatusOr<const EVP_MD*> md = internal::EvpHashFromHashType(hash_type);
  if (!md.ok()) {
    return md.status();
  }
  if (EVP_MD_size(*md) < tag_size) {
    // The key manager is responsible to security policies.
    // The checks here just ensure the preconditions of the primitive.
    // If this fails then something is wrong with the key manager.
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid tag size");
  }
  if (key.size() < kMinKeySize) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid key size");
  }
  return {absl::WrapUnique(new HmacBoringSsl(*md, tag_size, std::move(key)))};
}

absl::StatusOr<std::string> HmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  uint8_t buf[EVP_MAX_MD_SIZE];
  unsigned int out_len;
  // We assume that the buffer can be leaked safely in core dumps. This is ok
  // because we are in ComputeMac and hence we can assume that the MAC will be
  // published after this method anyways. In addition, we can expect that
  // BoringSSL will not use the buffer as a scratch pad to write sensitive data
  // (as this would be slow).
  internal::ScopedAssumeRegionCoreDumpSafe scoped =
      internal::ScopedAssumeRegionCoreDumpSafe(buf, EVP_MAX_MD_SIZE);

  const uint8_t* res = internal::CallWithCoreDumpProtection([&]() {
    return HMAC(md_, key_.data(), key_.size(),
                reinterpret_cast<const uint8_t*>(data.data()), data.size(), buf,
                &out_len);
  });
  // Declassify the tag. Safe because it is in a std::string anyhow and can
  // be given to the adversary (though the core can expose longer tags
  // than the user will).
  crypto::tink::internal::DfsanClearLabel(buf, EVP_MAX_MD_SIZE);
  if (res == nullptr) {
    // TODO(bleichen): We expect that BoringSSL supports the
    //   hashes that we use. Maybe we should have a status that indicates
    //   such mismatches between expected and actual behaviour.
    return absl::Status(absl::StatusCode::kInternal,
                        "BoringSSL failed to compute HMAC");
  }
  return std::string(reinterpret_cast<char*>(buf), tag_size_);
}

absl::Status HmacBoringSsl::VerifyMac(absl::string_view mac,
                                      absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  if (mac.size() != tag_size_) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "incorrect tag size");
  }
  internal::SecretBuffer buf(EVP_MAX_MD_SIZE);
  unsigned int out_len;
  const uint8_t* res = internal::CallWithCoreDumpProtection([&]() {
    return HMAC(md_, key_.data(), key_.size(),
                reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                buf.data(), &out_len);
  });
  if (res == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "BoringSSL failed to compute HMAC");
  }
  if (!internal::SafeCryptoMemEquals(buf.data(), mac.data(), tag_size_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "verification failed");
  }
  return absl::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
