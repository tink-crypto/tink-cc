// Copyright 2026 Google LLC
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

#include "tink/mac/internal/hmac_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/absl_check.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/md_util.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::HashType> ToSubtleHashType(
    HmacParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacParameters::HashType::kSha1:
      return subtle::HashType::SHA1;
    case HmacParameters::HashType::kSha224:
      return subtle::HashType::SHA224;
    case HmacParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case HmacParameters::HashType::kSha384:
      return subtle::HashType::SHA384;
    case HmacParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

class HmacBoringSslImpl : public Mac {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kRequiresBoringCrypto;

  HmacBoringSslImpl(const EVP_MD* md, uint32_t tag_size, SecretData key,
                    absl::string_view output_prefix,
                    absl::string_view message_suffix = "")
      : md_(md),
        tag_size_(tag_size),
        key_(std::move(key)),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> ComputeMac(absl::string_view data) const override;

  absl::Status VerifyMac(absl::string_view mac,
                         absl::string_view data) const override;

 private:
  const EVP_MD* const md_;
  const uint32_t tag_size_;
  const SecretData key_;
  const std::string output_prefix_;
  const std::string message_suffix_;
};

absl::StatusOr<std::string> HmacBoringSslImpl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);
  std::string data_with_suffix;
  if (!message_suffix_.empty()) {
    absl::StrAppend(&data_with_suffix, data, message_suffix_);
    data = data_with_suffix;
  }

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
  return absl::StrCat(
      output_prefix_,
      absl::string_view(reinterpret_cast<char*>(buf), tag_size_));
}

absl::Status HmacBoringSslImpl::VerifyMac(absl::string_view mac,
                                          absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  if (mac.size() != output_prefix_.size() + tag_size_) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "incorrect tag size");
  }
  if (!absl::StartsWith(mac, output_prefix_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "verification failed");
  }
  mac.remove_prefix(output_prefix_.size());
  std::string data_with_suffix;
  if (!message_suffix_.empty()) {
    absl::StrAppend(&data_with_suffix, data, message_suffix_);
    data = data_with_suffix;
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

}  // namespace

absl::StatusOr<std::unique_ptr<Mac>> NewHmacBoringSsl(const HmacKey& key) {
  ABSL_RETURN_IF_ERROR(CheckFipsCompatibility<HmacBoringSslImpl>());
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hash_type,
                        ToSubtleHashType(key.GetParameters().GetHashType()));
  ABSL_ASSIGN_OR_RETURN(const EVP_MD* md, EvpHashFromHashType(hash_type));
  ABSL_CHECK(md != nullptr);
  const int tag_size = key.GetParameters().CryptographicTagSizeInBytes();
  SecretData key_data = key.GetKeyBytes(GetPartialKeyAccess())
                            .Get(InsecureSecretKeyAccess::Get());
  if (key.GetParameters().GetVariant() == HmacParameters::Variant::kLegacy) {
    return std::make_unique<HmacBoringSslImpl>(
        md, static_cast<uint32_t>(tag_size), std::move(key_data),
        key.GetOutputPrefix(), absl::string_view("\0", 1));
  }
  return std::make_unique<HmacBoringSslImpl>(
      md, static_cast<uint32_t>(tag_size), std::move(key_data),
      key.GetOutputPrefix());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
