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

#include "tink/mac/internal/aes_cmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "openssl/cmac.h"
#include "openssl/evp.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/safe_stringops.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"

namespace crypto {
namespace tink {
namespace internal {
// CMAC key sizes in bytes.
// The small key size is used only to check RFC 4493's test vectors due to
// the attack described in
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf. We
// check this restriction in AesCmacManager.
static constexpr size_t kSmallKeySize = 16;
static constexpr size_t kBigKeySize = 32;
static constexpr size_t kMaxTagSize = 16;

namespace {

// Computes the CMAC of `data` + `suffix` using `key` and writes the result to
// `tag_ptr[0..kMaxTagSize-1]`.
//
// `data` and `suffix` are separate arguments so the caller can avoid a copy.
bool ComputeMacInternal(const SecretData& key, uint8_t* tag_ptr,
                        absl::string_view data, absl::string_view suffix) {
  internal::SslUniquePtr<CMAC_CTX> context(CMAC_CTX_new());
  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCbcCipherForKeySize(key.size());
  if (!cipher.ok()) {
    return false;
  }
  const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data.data());
  const uint8_t* suffix_ptr = reinterpret_cast<const uint8_t*>(suffix.data());
  size_t len = 0;
  return internal::CallWithCoreDumpProtection([&, cipher = *cipher]() {
    if (CMAC_Init(context.get(), key.data(), key.size(), cipher, nullptr) <=
            0 ||
        CMAC_Update(context.get(), data_ptr, data.size()) <= 0 ||
        (!suffix.empty() &&
         CMAC_Update(context.get(), suffix_ptr, suffix.size()) <= 0) ||
        CMAC_Final(context.get(), tag_ptr, &len) == 0) {
      return false;
    }
    return true;
  });
}

class AesCmacBoringSslImpl : public Mac {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  AesCmacBoringSslImpl(SecretData key, uint32_t tag_size,
                       absl::string_view output_prefix,
                       absl::string_view message_suffix)
      : key_(std::move(key)),
        tag_size_(tag_size),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> ComputeMac(absl::string_view data) const override;

  absl::Status VerifyMac(absl::string_view mac,
                         absl::string_view data) const override;

 private:
  const SecretData key_;
  const uint32_t tag_size_;
  std::string output_prefix_;
  std::string message_suffix_;
};

absl::StatusOr<std::string> AesCmacBoringSslImpl::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  const size_t output_prefix_size = output_prefix_.size();
  std::string result = output_prefix_;
  subtle::ResizeStringUninitialized(&result, output_prefix_size + kMaxTagSize);

  uint8_t* result_mac_ptr =
      reinterpret_cast<uint8_t*>(&result[output_prefix_size]);
  internal::ScopedAssumeRegionCoreDumpSafe scoped(result_mac_ptr, kMaxTagSize);
  if (!ComputeMacInternal(key_, result_mac_ptr, data, message_suffix_)) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to compute CMAC");
  }
  // Declassify the tag. Safe because it is in a std::string anyhow and can
  // be given to the adversary (though the core dump could expose longer tags
  // than the user will).
  crypto::tink::internal::DfsanClearLabel(result_mac_ptr, kMaxTagSize);
  result.resize(output_prefix_size + tag_size_);

  return result;
}

absl::Status AesCmacBoringSslImpl::VerifyMac(absl::string_view mac,
                                             absl::string_view data) const {
  if (!absl::StartsWith(mac, output_prefix_)) {
    return absl::InvalidArgumentError("Prefix mismatch");
  }
  mac.remove_prefix(output_prefix_.size());

  if (mac.size() != tag_size_) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Incorrect tag size: expected %d, found %d", tag_size_,
                     mac.size());
  }
  internal::SecretBuffer computed_mac(kMaxTagSize);

  if (!ComputeMacInternal(key_, computed_mac.data(), data, message_suffix_)) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to compute CMAC");
  }
  computed_mac.resize(tag_size_);

  if (!internal::SafeCryptoMemEquals(computed_mac.data(), mac.data(),
                                     tag_size_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "CMAC verification failed");
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<Mac>> NewAesCmacBoringSsl(
    const AesCmacKey& key) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<AesCmacBoringSslImpl>());

  if (key.GetParameters().KeySizeInBytes() != kSmallKeySize &&
      key.GetParameters().KeySizeInBytes() != kBigKeySize) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid key size: expected %d or %d, found %d",
                     kSmallKeySize, kBigKeySize,
                     key.GetParameters().KeySizeInBytes());
  }
  if (static_cast<size_t>(key.GetParameters().CryptographicTagSizeInBytes()) >
      kMaxTagSize) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid tag size: expected at most %d, found %d",
                     kMaxTagSize,
                     key.GetParameters().CryptographicTagSizeInBytes());
  }
  return std::make_unique<AesCmacBoringSslImpl>(
      key.GetKeyBytes(GetPartialKeyAccess())
          .Get(InsecureSecretKeyAccess::Get()),
      key.GetParameters().CryptographicTagSizeInBytes(), key.GetOutputPrefix(),
      key.GetParameters().GetVariant() == AesCmacParameters::Variant::kLegacy
          ? absl::string_view("\0", 1)
          : "");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
