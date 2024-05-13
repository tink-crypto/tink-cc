// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/signature/internal/slh_dsa_sign_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "openssl/experimental/spx.h"
#undef OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// static
util::StatusOr<std::unique_ptr<PublicKeySign>> SlhDsaSignBoringSsl::New(
    const SlhDsaPrivateKey &private_key) {
  auto status = internal::CheckFipsCompatibility<SlhDsaSignBoringSsl>();
  if (!status.ok()) {
    return status;
  }
  return {absl::WrapUnique(new SlhDsaSignBoringSsl(std::move(private_key)))};
}

util::StatusOr<std::string> SlhDsaSignBoringSsl::Sign(
    absl::string_view data) const {
  // The signature will be prepended with the output prefix for TINK keys.
  std::string signature(private_key_.GetOutputPrefix());
  subtle::ResizeStringUninitialized(
      &signature, SPX_SIGNATURE_BYTES + private_key_.GetOutputPrefix().size());

  SPX_sign(reinterpret_cast<uint8_t *>(signature.data() +
                                       private_key_.GetOutputPrefix().size()),
           private_key_.GetPrivateKeyBytes(GetPartialKeyAccess())
               .Get(InsecureSecretKeyAccess::Get())
               .data(),
           reinterpret_cast<const uint8_t *>(data.data()), data.size(),
           /*randomized=*/1);

  return signature;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
