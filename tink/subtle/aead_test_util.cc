// Copyright 2019 Google LLC
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
#include "tink/subtle/aead_test_util.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/subtle/test_util.h"

namespace crypto {
namespace tink {

absl::Status EncryptThenDecrypt(const Aead& encrypter, const Aead& decrypter,
                                absl::string_view message,
                                absl::string_view aad) {
  absl::StatusOr<std::string> encryption_or = encrypter.Encrypt(message, aad);
  if (!encryption_or.status().ok()) return encryption_or.status();
  absl::StatusOr<std::string> decryption_or =
      decrypter.Decrypt(encryption_or.value(), aad);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.value() != message) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Message/Decryption mismatch");
  }
  return absl::OkStatus();
}

absl::Status EncryptThenDecrypt(const CordAead& encrypter,
                                const CordAead& decrypter,
                                absl::string_view message,
                                absl::string_view aad) {
  absl::Cord message_cord = absl::Cord(message);
  absl::Cord aad_cord = absl::Cord(aad);
  absl::StatusOr<absl::Cord> encryption_or =
      encrypter.Encrypt(message_cord, aad_cord);
  if (!encryption_or.status().ok()) return encryption_or.status();
  absl::StatusOr<absl::Cord> decryption_or =
      decrypter.Decrypt(encryption_or.value(), aad_cord);
  if (!decryption_or.status().ok()) return decryption_or.status();
  if (decryption_or.value() != message) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Message/Decryption mismatch");
  }
  return absl::OkStatus();
}

}  // namespace tink
}  // namespace crypto
