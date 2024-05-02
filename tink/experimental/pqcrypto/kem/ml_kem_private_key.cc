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

#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/experimental/kyber.h"
#include "openssl/mem.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<MlKemPrivateKey> MlKemPrivateKey::Create(
    const MlKemPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  if (private_key_bytes.size() != KYBER_PRIVATE_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid ML-KEM private key size. Only ",
                                     KYBER_PRIVATE_KEY_BYTES,
                                     "-byte keys are currently supported."));
  }

  if (public_key.GetParameters().GetKeySize() != 768) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-KEM key size. Only ML-KEM-768 is "
                        "currently supported.");
  }

  // Confirm that the private key and public key are a valid ML-KEM key pair.
  auto bssl_private_key = util::MakeSecretUniquePtr<KYBER_private_key>();
  auto private_key_view =
      private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get());
  CBS cbs;
  CBS_init(&cbs, reinterpret_cast<const uint8_t*>(private_key_view.data()),
           private_key_view.size());
  if (!KYBER_parse_private_key(bssl_private_key.get(), &cbs)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-KEM private key.");
  }

  auto bssl_public_key = absl::make_unique<KYBER_public_key>();
  KYBER_public_from_private(bssl_public_key.get(), bssl_private_key.get());

  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(KYBER_PUBLIC_KEY_BYTES);

  CBB cbb;
  size_t size;
  if (!CBB_init_fixed(&cbb,
                      reinterpret_cast<uint8_t*>(&public_key_bytes_regen[0]),
                      KYBER_PUBLIC_KEY_BYTES) ||
      !KYBER_marshal_public_key(&cbb, bssl_public_key.get()) ||
      !CBB_finish(&cbb, nullptr, &size) || size != KYBER_PUBLIC_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-KEM public key.");
  }

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(),
                    KYBER_PUBLIC_KEY_BYTES) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid ML-KEM key pair");
  }

  return MlKemPrivateKey(public_key, private_key_bytes);
}

bool MlKemPrivateKey::operator==(const Key& other) const {
  const MlKemPrivateKey* that = dynamic_cast<const MlKemPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
