// Copyright 2017 Google LLC
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

#include "tink/subtle/aes_cmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
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
namespace subtle {
// CMAC key sizes in bytes.
// The small key size is used only to check RFC 4493's test vectors due to
// the attack described in
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf. We
// check this restriction in AesCmacManager.
static constexpr size_t kSmallKeySize = 16;
static constexpr size_t kBigKeySize = 32;
static constexpr size_t kMaxTagSize = 16;

namespace {

// Computes the CMAC of `data` using `key` and writes the result to
// `tag_ptr[0..kMaxTagSize-1]`.
bool ComputeMacInternal(const SecretData& key, uint8_t* tag_ptr,
                        absl::string_view data) {
  internal::SslUniquePtr<CMAC_CTX> context(CMAC_CTX_new());
  absl::StatusOr<const EVP_CIPHER*> cipher =
      internal::GetAesCbcCipherForKeySize(key.size());
  if (!cipher.ok()) {
    return false;
  }
  const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(data.data());
  size_t len = 0;
  return internal::CallWithCoreDumpProtection([&]() {
    if (CMAC_Init(context.get(), key.data(), key.size(), *cipher, nullptr) <=
            0 ||
        CMAC_Update(context.get(), data_ptr, data.size()) <= 0 ||
        CMAC_Final(context.get(), tag_ptr, &len) == 0) {
      return false;
    }
    return true;
  });
}

}  // namespace

// static
absl::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(SecretData key,
                                                           uint32_t tag_size) {
  auto status = internal::CheckFipsCompatibility<AesCmacBoringSsl>();
  if (!status.ok()) return status;

  if (key.size() != kSmallKeySize && key.size() != kBigKeySize) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid key size: expected %d or %d, found %d",
                     kSmallKeySize, kBigKeySize, key.size());
  }
  if (tag_size > kMaxTagSize) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid tag size: expected lower than %d, found %d",
                     kMaxTagSize, tag_size);
  }
  return {
      absl::WrapUnique(new AesCmacBoringSsl(std::move(key), tag_size, "", ""))};
}

// static
absl::StatusOr<std::unique_ptr<Mac>> AesCmacBoringSsl::New(
    const AesCmacKey& key) {
  auto status = internal::CheckFipsCompatibility<AesCmacBoringSsl>();
  if (!status.ok()) return status;

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
  return {absl::WrapUnique(new AesCmacBoringSsl(
      key.GetKeyBytes(GetPartialKeyAccess())
          .Get(InsecureSecretKeyAccess::Get()),
      key.GetParameters().CryptographicTagSizeInBytes(), key.GetOutputPrefix(),
      key.GetParameters().GetVariant() == AesCmacParameters::Variant::kLegacy
          ? absl::string_view("\0", 1)
          : ""))};
}

absl::StatusOr<std::string> AesCmacBoringSsl::ComputeMacNoPrefix(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  std::string result;
  ResizeStringUninitialized(&result, kMaxTagSize);
  uint8_t* result_ptr = reinterpret_cast<uint8_t*>(&result[0]);
  internal::ScopedAssumeRegionCoreDumpSafe scoped(result_ptr, kMaxTagSize);
  if (!ComputeMacInternal(key_, result_ptr, data)) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to compute CMAC");
  }
  // Declassify the tag. Safe because it is in a std::string anyhow and can
  // be given to the adversary (though the core dump could expose longer tags
  // than the user will).
  crypto::tink::internal::DfsanClearLabel(result_ptr, kMaxTagSize);
  result.resize(tag_size_);
  return result;
}

absl::Status AesCmacBoringSsl::VerifyMacNoPrefix(
    absl::string_view mac, absl::string_view data) const {
  if (mac.size() != tag_size_) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Incorrect tag size: expected %d, found %d", tag_size_,
                     mac.size());
  }
  internal::SecretBuffer computed_mac(kMaxTagSize);

  if (!ComputeMacInternal(key_, computed_mac.data(), data)) {
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

absl::StatusOr<std::string> AesCmacBoringSsl::ComputeMac(
    absl::string_view data) const {
  absl::StatusOr<std::string> raw_sig;
  if (!message_suffix_.empty()) {
    std::string message = absl::StrCat(data, message_suffix_);
    raw_sig = ComputeMacNoPrefix(message);
  } else {
    raw_sig = ComputeMacNoPrefix(data);
  }
  if (output_prefix_.empty()) {
    return raw_sig;
  }
  if (!raw_sig.ok()) {
    return raw_sig;
  }
  return absl::StrCat(output_prefix_, *raw_sig);
}

absl::Status AesCmacBoringSsl::VerifyMac(
    absl::string_view mac, absl::string_view data) const {
  if (!absl::StartsWith(mac, output_prefix_)) {
    return absl::InvalidArgumentError("Prefix mismatch");
  }
  mac.remove_prefix(output_prefix_.size());
  if (message_suffix_.empty()) {
    return VerifyMacNoPrefix(mac, data);
  } else {
    return VerifyMacNoPrefix(mac, absl::StrCat(data, message_suffix_));
  }
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
