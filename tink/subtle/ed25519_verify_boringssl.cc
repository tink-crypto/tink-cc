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

#include "tink/subtle/ed25519_verify_boringssl.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "openssl/evp.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_public_key.h"

namespace crypto {
namespace tink {
namespace subtle {

constexpr int kEd25519SignatureLenInBytes = 64;

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Ed25519VerifyBoringSsl::New(
    const Ed25519PublicKey &public_key) {
  return New(public_key.GetPublicKeyBytes(GetPartialKeyAccess()),
             public_key.GetOutputPrefix(),
             public_key.GetParameters().GetVariant() ==
                     Ed25519Parameters::Variant::kLegacy
                 ? std::string(1, 0)
                 : "");
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Ed25519VerifyBoringSsl::New(
    absl::string_view public_key, absl::string_view output_prefix,
    absl::string_view message_suffix) {
  auto status = internal::CheckFipsCompatibility<Ed25519VerifyBoringSsl>();
  if (!status.ok()) return status;

  if (public_key.length() !=
      static_cast<size_t>(internal::Ed25519KeyPubKeySize())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 public key size (%d). "
                        "The only valid size is %d.",
                        public_key.length(), internal::Ed25519KeyPubKeySize()));
  }

  // Generate a new EVP_PKEY key and populate it with the public key data.
  internal::SslUniquePtr<EVP_PKEY> ssl_pub_key(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, /*unused=*/nullptr,
      reinterpret_cast<const uint8_t *>(public_key.data()),
      internal::Ed25519KeyPrivKeySize()));
  if (ssl_pub_key == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_PKEY_new_raw_public_key failed");
  }

  return {absl::WrapUnique(new Ed25519VerifyBoringSsl(
      std::move(ssl_pub_key), output_prefix, message_suffix))};
}

absl::Status Ed25519VerifyBoringSsl::VerifyWithoutPrefix(
    absl::string_view signature, absl::string_view data) const {
  signature = internal::EnsureStringNonNull(signature);
  data = internal::EnsureStringNonNull(data);

  if (signature.size() != kEd25519SignatureLenInBytes) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Invalid ED25519 signature size (%d). "
                        "The signature must be %d bytes long.",
                        signature.size(), kEd25519SignatureLenInBytes));
  }

  internal::SslUniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_create());
  // `type` must be set to nullptr with Ed25519.
  if (EVP_DigestVerifyInit(md_ctx.get(), /*pctx=*/nullptr, /*type=*/nullptr,
                           /*e=*/nullptr, public_key_.get()) != 1) {
    return absl::Status(absl::StatusCode::kInternal,
                        "EVP_DigestVerifyInit failed.");
  }

  if (EVP_DigestVerify(
          md_ctx.get(),
          /*sig=*/reinterpret_cast<const uint8_t *>(signature.data()),
          signature.size(),
          /*data=*/reinterpret_cast<const uint8_t *>(data.data()),
          data.size()) != 1) {
    return absl::Status(absl::StatusCode::kInternal, "Signature is not valid.");
  }

  return absl::OkStatus();
}

absl::Status Ed25519VerifyBoringSsl::Verify(absl::string_view signature,
                                            absl::string_view data) const {
  if (output_prefix_.empty() && message_suffix_.empty()) {
    return VerifyWithoutPrefix(signature, data);
  }
  if (!absl::StartsWith(signature, output_prefix_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "OutputPrefix does not match");
  }
  // Stores a copy of the data in case message_suffix_ is not empty.
  // Needs to stay alive until this method is done.
  std::string data_copy_holder;
  if (!message_suffix_.empty()) {
    data_copy_holder = absl::StrCat(data, message_suffix_);
    data = data_copy_holder;
  }
  return VerifyWithoutPrefix(absl::StripPrefix(signature, output_prefix_),
                             data);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
