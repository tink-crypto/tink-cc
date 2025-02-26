// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/slh_dsa_private_key.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/mem.h"
#include "openssl/slhdsa.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/signature/slh_dsa_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

absl::StatusOr<SlhDsaPrivateKey> SlhDsaPrivateKey::Create(
    const SlhDsaPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  // Only 64-byte private keys are currently supported.
  if (private_key_bytes.size() != SLHDSA_SHA2_128S_PRIVATE_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SLH-DSA private key length must be 64 bytes.");
  }

  if (public_key.GetParameters().GetPrivateKeySizeInBytes() !=
      private_key_bytes.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Private key size does not match parameters");
  }
  // Confirm that the private key and public key are a valid SLH-DSA key pair.
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES);

  SLHDSA_SHA2_128S_public_from_private(
      reinterpret_cast<uint8_t*>(&public_key_bytes_regen[0]),
      reinterpret_cast<const uint8_t*>(
          private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get()).data()));

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(),
                    SLHDSA_SHA2_128S_PUBLIC_KEY_BYTES) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid SLH-DSA key pair");
  }

  return SlhDsaPrivateKey(public_key, private_key_bytes);
}

bool SlhDsaPrivateKey::operator==(const Key& other) const {
  const SlhDsaPrivateKey* that = dynamic_cast<const SlhDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
