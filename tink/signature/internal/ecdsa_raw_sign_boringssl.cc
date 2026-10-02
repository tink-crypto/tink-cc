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

#include "tink/signature/internal/ecdsa_raw_sign_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/util.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {

// static
absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>>
EcdsaRawSignBoringSsl::New(internal::SslUniquePtr<EC_KEY> key,
                           subtle::EcdsaSignatureEncoding encoding) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<EcdsaRawSignBoringSsl>());
  if (key == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Key cannot be null");
  }
  return {
      absl::WrapUnique(new EcdsaRawSignBoringSsl(std::move(key), encoding))};
}

// static
absl::StatusOr<std::unique_ptr<EcdsaRawSignBoringSsl>>
EcdsaRawSignBoringSsl::New(const internal::EcKey& ec_key,
                           subtle::EcdsaSignatureEncoding encoding) {
  ABSL_RETURN_IF_ERROR(
      internal::CheckFipsCompatibility<EcdsaRawSignBoringSsl>());

  internal::SslUniquePtr<EC_KEY> key(EC_KEY_new());
  absl::Status result = CallWithCoreDumpProtection([&]() -> absl::Status {
    // Check curve.
    ABSL_ASSIGN_OR_RETURN(internal::SslUniquePtr<EC_GROUP> group,
                          internal::EcGroupFromCurveType(ec_key.curve));
    EC_KEY_set_group(key.get(), group.get());

    // Check key.
    ABSL_ASSIGN_OR_RETURN(
        internal::SslUniquePtr<EC_POINT> pub_key,
        internal::GetEcPoint(ec_key.curve, ec_key.pub_x, ec_key.pub_y));

    if (!EC_KEY_set_public_key(key.get(), pub_key.get())) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid public key: ", internal::GetSslErrors()));
    }

    internal::SslUniquePtr<BIGNUM> priv_key(
        BN_bin2bn(ec_key.priv.data(), ec_key.priv.size(), nullptr));
    if (!EC_KEY_set_private_key(key.get(), priv_key.get())) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid private key: ", internal::GetSslErrors()));
    }
    return absl::OkStatus();
  });
  ABSL_RETURN_IF_ERROR(result);
  return New(std::move(key), encoding);
}

absl::StatusOr<std::string> EcdsaRawSignBoringSsl::SignDigest(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  // Compute the raw signature.
  size_t signature_buffer_size = ECDSA_size(key_.get());
  std::vector<uint8_t> buffer(signature_buffer_size);
  // We allow core dump leakage of information written into the buffer. This is
  // anyhow only the signature, which is fine to give to the adversary.
  ScopedAssumeRegionCoreDumpSafe scope(buffer.data(), signature_buffer_size);
  absl::StatusOr<int> signature_length =
      CallWithCoreDumpProtection([&]() -> absl::StatusOr<int> {
        unsigned int sig_length;
        int result = ECDSA_sign(0 /* unused */,
                          reinterpret_cast<const uint8_t*>(data.data()),
                          data.size(), buffer.data(), &sig_length, key_.get());
        if (result != 1) {
          return absl::Status(absl::StatusCode::kInternal,
                              "BoringSSL signing failed");
        }
        // We clear the label from the signature length -- the signature is
        // now public, so the label can be cleared.
        DfsanClearLabel(&sig_length, sizeof(sig_length));
        return sig_length;
      });
  if (!signature_length.ok()) {
    return signature_length.status();
  }

  // We now remove DFSan labels from the signature - this is fine to leak.
  DfsanClearLabel(buffer.data(), *signature_length);
  if (encoding_ == subtle::EcdsaSignatureEncoding::IEEE_P1363) {
    return internal::EcSignatureDerToIeee(
        EC_KEY_get0_group(key_.get()),
        absl::string_view(reinterpret_cast<char*>(buffer.data()),
                          *signature_length));
  }

  return std::string(reinterpret_cast<char*>(buffer.data()), *signature_length);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
