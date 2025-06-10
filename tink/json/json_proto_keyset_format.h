// Copyright 2025 Google LLC
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

#ifndef TINK_JSON_JSON_PROTO_KEYSET_FORMAT_H_
#define TINK_JSON_JSON_PROTO_KEYSET_FORMAT_H_

#include <string>
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/secret_key_access_token.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {

// Serializes a keyset into a binary string in "JsonProtoKeysetFormat".
// This function can serialize both keyset with or without secret key material.
absl::StatusOr<SecretData>
SerializeKeysetToJsonProtoKeysetFormat(const KeysetHandle& keyset_handle,
                                   SecretKeyAccessToken token);

// Parses a keyset from a binary string in "JsonProtoKeysetFormat".
// This function can parse both keyset with or without secret key material.
absl::StatusOr<KeysetHandle> ParseKeysetFromJsonProtoKeysetFormat(
    absl::string_view serialized_keyset, SecretKeyAccessToken token);

// Serializes a keyset into a binary string in "JsonProtoKeysetFormat".
// This function will fail if the keyset contains secret key material.
absl::StatusOr<std::string>
SerializeKeysetWithoutSecretToJsonProtoKeysetFormat(
    const KeysetHandle& keyset_handle);

// Parses a keyset from a binary string in "JsonProtoKeysetFormat".
// This function will fail if the keyset contains secret key material.
absl::StatusOr<KeysetHandle>
ParseKeysetWithoutSecretFromJsonProtoKeysetFormat(
    absl::string_view serialized_keyset);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JSON_PROTO_KEYSET_FORMAT_H_
