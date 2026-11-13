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

#include "tink/signature/internal/ed25519_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/digest.h"
#endif
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

constexpr int kEd25519SignatureLenInBytes = 64;

class Ed25519SignBoringSslImpl : public PublicKeySign {
 public:
  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

  explicit Ed25519SignBoringSslImpl(internal::SslUniquePtr<EVP_PKEY> priv_key,
                                    absl::string_view output_prefix,
                                    absl::string_view message_suffix)
      : priv_key_(std::move(priv_key)),
        output_prefix_(output_prefix),
        message_suffix_(message_suffix) {}

  absl::StatusOr<std::string> Sign(absl::string_view data) const override;

 private:
  absl::StatusOr<std::string> SignWithoutPrefix(absl::string_view data) const;

  const internal::SslUniquePtr<EVP_PKEY> priv_key_;
  const std::string output_prefix_;
  const std::string message_suffix_;
};

absl::StatusOr<std::string> Ed25519SignBoringSslImpl::SignWithoutPrefix(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);

  std::string out_sig;
  out_sig.resize(kEd25519SignatureLenInBytes);
  // We ignore writes in the out_sig for core dump safety  -- after all, the
  // signature is what can be leaked to the adversary anyhow.
  internal::ScopedAssumeRegionCoreDumpSafe scope(out_sig.data(),
                                                 kEd25519SignatureLenInBytes);
  internal::SslUniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_create());
  if (md_ctx == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_MD_CTX_create failed.");
  }
  size_t sig_len = kEd25519SignatureLenInBytes;
  // type must be set to nullptr with Ed25519.
  // See https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html.
  bool success = internal::CallWithCoreDumpProtection([&]() {
    return EVP_DigestSignInit(md_ctx.get(), /*pctx=*/nullptr, /*type=*/nullptr,
                              /*e=*/nullptr, priv_key_.get()) == 1 &&
           EVP_DigestSign(
               md_ctx.get(), reinterpret_cast<uint8_t*>(&out_sig[0]), &sig_len,
               /*data=*/reinterpret_cast<const uint8_t*>(data.data()),
               data.size()) == 1;
  });
  if (!success) {
    return absl::Status(absl::StatusCode::kInternal, "Signing failed.");
  }
  // It is fine to leak the signature to the adversary so we can now clear the
  // label.
  internal::DfsanClearLabel(out_sig.data(), kEd25519SignatureLenInBytes);
  return out_sig;
}

absl::StatusOr<std::string> Ed25519SignBoringSslImpl::Sign(
    absl::string_view data) const {
  absl::StatusOr<std::string> signature_without_prefix_;
  if (message_suffix_.empty()) {
    signature_without_prefix_ = SignWithoutPrefix(data);
  } else {
    signature_without_prefix_ =
        SignWithoutPrefix(absl::StrCat(data, message_suffix_));
  }
  if (!signature_without_prefix_.ok()) {
    return signature_without_prefix_.status();
  }
  if (output_prefix_.empty()) {
    return signature_without_prefix_;
  }
  return absl::StrCat(output_prefix_, *signature_without_prefix_);
}

}  // namespace

absl::StatusOr<std::unique_ptr<PublicKeySign>> NewEd25519SignBoringSsl(
    const Ed25519PrivateKey& key) {
  auto status = internal::CheckFipsCompatibility<Ed25519SignBoringSslImpl>();
  if (!status.ok()) return status;

  const SecretData& private_key = key.GetPrivateKeyBytes(GetPartialKeyAccess())
                                      .Get(InsecureSecretKeyAccess::Get());
  if (private_key.size() !=
      static_cast<size_t>(internal::Ed25519KeyPrivKeySize())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.size(), internal::Ed25519KeyPrivKeySize()));
  }

  internal::SslUniquePtr<EVP_PKEY> ssl_priv_key(
      crypto::tink::internal::CallWithCoreDumpProtection([&]() {
        return EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, /*unused=*/nullptr, private_key.data(),
            internal::Ed25519KeyPrivKeySize());
      }));
  if (ssl_priv_key == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_private_key failed");
  }

  return std::make_unique<Ed25519SignBoringSslImpl>(
      std::move(ssl_priv_key), key.GetOutputPrefix(),
      key.GetParameters().GetVariant() == Ed25519Parameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
