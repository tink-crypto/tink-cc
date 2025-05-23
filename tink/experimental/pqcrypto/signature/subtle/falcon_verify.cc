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

#include "tink/experimental/pqcrypto/signature/subtle/falcon_verify.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/internal/fips_utils.h"
#include "tink/public_key_verify.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

extern "C" {
#include "third_party/pqclean/crypto_sign/falcon-1024/api.h"
#include "third_party/pqclean/crypto_sign/falcon-512/api.h"
}

namespace crypto {
namespace tink {
namespace subtle {

// static
absl::StatusOr<std::unique_ptr<PublicKeyVerify>> FalconVerify::New(
    const FalconPublicKeyPqclean &public_key) {
  auto status = internal::CheckFipsCompatibility<FalconVerify>();
  if (!status.ok()) return status;

  return {
      absl::WrapUnique<FalconVerify>(new FalconVerify(public_key))};
}

absl::Status FalconVerify::Verify(absl::string_view signature,
                                  absl::string_view data) const {
  int32_t key_size = public_key_.GetKey().size();
  int result = 1;

  switch (key_size) {
    case kFalcon512PublicKeySize: {
      result = PQCLEAN_FALCON512_crypto_sign_verify(
          reinterpret_cast<const uint8_t *>(signature.data()), signature.size(),
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(public_key_.GetKey().data()));
      break;
    }
    case kFalcon1024PublicKeySize: {
      result = PQCLEAN_FALCON1024_crypto_sign_verify(
          reinterpret_cast<const uint8_t *>(signature.data()), signature.size(),
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(public_key_.GetKey().data()));
      break;
    }
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Invalid keysize.");
  }

  if (result != 0) {
    return absl::Status(absl::StatusCode::kInternal, "Signature is not valid.");
  }

  return absl::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
