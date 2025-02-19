// Copyright 2019 Google LLC
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

#include "tink/subtle/ed25519_sign_boringssl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "openssl/evp.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

constexpr int kEd25519SignatureLenInBytes = 64;

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    util::SecretData private_key, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  auto status = internal::CheckFipsCompatibility<Ed25519SignBoringSsl>();
  if (!status.ok()) return status;

  // OpenSSL/BoringSSL consider the ED25519's private key to be: private_key ||
  // public_key.
  const int kSslPrivateKeySize =
      internal::Ed25519KeyPrivKeySize() + internal::Ed25519KeyPubKeySize();

  if (private_key.size() != kSslPrivateKeySize) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 private key size (%d). "
                        "The only valid size is %d.",
                        private_key.size(), kSslPrivateKeySize));
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

  return {absl::WrapUnique(new Ed25519SignBoringSsl(
      std::move(ssl_priv_key), output_prefix, message_suffix))};
}

util::StatusOr<std::string> Ed25519SignBoringSsl::SignWithoutPrefix(
    absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);

  std::string out_sig;
  out_sig.resize(kEd25519SignatureLenInBytes);
  // We ignore writes in the out_sig for core dump safety  -- after all, the
  // signature is what can be leaked to the adversary anyhow.
  internal::ScopedAssumeRegionCoreDumpSafe scope(out_sig.data(),
                                                 kEd25519SignatureLenInBytes);
  internal::SslUniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_create());
  size_t sig_len = kEd25519SignatureLenInBytes;
  // type must be set to nullptr with Ed25519.
  // See https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html.
  bool success = internal::CallWithCoreDumpProtection([&]() {
    return EVP_DigestSignInit(md_ctx.get(), /*pctx=*/nullptr, /*type=*/nullptr,
                              /*e=*/nullptr, priv_key_.get()) == 1 &&
           EVP_DigestSign(
               md_ctx.get(), reinterpret_cast<uint8_t *>(&out_sig[0]),
               &sig_len,
               /*data=*/reinterpret_cast<const uint8_t *>(data.data()),
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

util::StatusOr<std::string> Ed25519SignBoringSsl::Sign(
    absl::string_view data) const {
  util::StatusOr<std::string> signature_without_prefix_;
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

util::StatusOr<std::unique_ptr<PublicKeySign>> Ed25519SignBoringSsl::New(
    const Ed25519PrivateKey &key) {
  internal::SecretBuffer private_key = util::internal::AsSecretBuffer(
      key.GetPrivateKeyBytes(GetPartialKeyAccess())
          .Get(InsecureSecretKeyAccess::Get()));
  std::string public_key =
      std::string(key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess()));
  size_t private_key_size = private_key.size();
  private_key.resize(private_key.size() + public_key.size());
  memcpy(private_key.data() + private_key_size, public_key.data(),
         public_key.size());

  return New(
      util::internal::AsSecretData(std::move(private_key)),
      key.GetOutputPrefix(),
      key.GetParameters().GetVariant() == Ed25519Parameters::Variant::kLegacy
          ? std::string(1, 0)
          : "");
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
