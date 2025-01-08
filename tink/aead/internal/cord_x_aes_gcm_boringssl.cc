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

#include "tink/aead/internal/cord_x_aes_gcm_boringssl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/internal/base_x_aes_gcm.h"
#include "tink/aead/internal/cord_aes_gcm_boringssl.h"
#include "tink/aead/internal/cord_utils.h"
#include "tink/aead/x_aes_gcm_key.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::CordAead;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::util::SecretData;

class CordXAesGcmBoringSsl : public CordAead {
 public:
  explicit CordXAesGcmBoringSsl(BaseXAesGcm base_x_aes_gcm)
      : base_x_aes_gcm_(std::move(base_x_aes_gcm)) {}

  crypto::tink::util::StatusOr<absl::Cord> Encrypt(
      absl::Cord plaintext, absl::Cord associated_data) const override {
    // TODO(b/354285352): Consider using RAND_BYTES once for salt + IV.
    std::string salt = Random::GetRandomBytes(base_x_aes_gcm_.salt_size());

    absl::StatusOr<SecretData> derived_key =
        base_x_aes_gcm_.DerivePerMessageKey(salt);
    if (!derived_key.ok()) {
      return derived_key.status();
    }
    util::StatusOr<std::unique_ptr<CordAead>> aead =
        CordAesGcmBoringSsl::New(*derived_key);
    if (!aead.ok()) {
      return aead.status();
    }
    util::StatusOr<absl::Cord> ciphertext =
        (*aead)->Encrypt(plaintext, associated_data);
    (*ciphertext).Prepend(std::move(salt));
    return *ciphertext;
  }

  crypto::tink::util::StatusOr<absl::Cord> Decrypt(
      absl::Cord ciphertext, absl::Cord associated_data) const override {
    if (ciphertext.size() < base_x_aes_gcm_.min_ct_size()) {
      return absl::InvalidArgumentError(
          absl::StrFormat("ciphertext too short, expected at least %d bytes",
                          base_x_aes_gcm_.min_ct_size()));
    }
    char salt[BaseXAesGcm::kMaxSaltSize];
    CordReader(ciphertext).ReadN(base_x_aes_gcm_.salt_size(), salt);
    ciphertext.RemovePrefix(base_x_aes_gcm_.salt_size());

    absl::StatusOr<SecretData> derived_key =
        base_x_aes_gcm_.DerivePerMessageKey(
            absl::string_view(salt, base_x_aes_gcm_.salt_size()));
    if (!derived_key.ok()) {
      return derived_key.status();
    }
    util::StatusOr<std::unique_ptr<CordAead>> aead =
        CordAesGcmBoringSsl::New(*derived_key);
    return (*aead)->Decrypt(std::move(ciphertext), associated_data);
  }

 private:
  BaseXAesGcm base_x_aes_gcm_;
};

}  // namespace

crypto::tink::util::StatusOr<std::unique_ptr<CordAead>> NewCordXAesGcmBoringSsl(
    const XAesGcmKey& key) {
  absl::StatusOr<BaseXAesGcm> base_x_aes_gcm = BaseXAesGcm::New(key);
  if (!base_x_aes_gcm.ok()) {
    return base_x_aes_gcm.status();
  }
  return std::make_unique<CordXAesGcmBoringSsl>(*std::move(base_x_aes_gcm));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
