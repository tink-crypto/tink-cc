// Copyright 2026 Google LLC.
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

#include "tink/aead/xchacha20_poly1305_key_manager.h"

#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/secret_data.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {

absl::StatusOr<std::unique_ptr<Aead>>
XChaCha20Poly1305KeyManager::AeadFactory::Create(
    const google::crypto::tink::XChaCha20Poly1305Key& key) const {
  return subtle::XChacha20Poly1305BoringSsl::New(
      util::SecretDataFromStringView(key.key_value()));
}

}  // namespace tink
}  // namespace crypto
