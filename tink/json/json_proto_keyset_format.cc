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

#include "tink/json/json_proto_keyset_format.h"

#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "google/protobuf/json/json.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/json/internal/tink_type_resolver.h"
#include "tink/keyset_handle.h"
#include "tink/proto_keyset_format.h"
#include "tink/secret_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::google::protobuf::json::JsonToBinaryString;
using ::google::protobuf::json::ParseOptions;
using ::google::protobuf::json::PrintOptions;

namespace {

using ::crypto::tink::internal::SecretBuffer;

const char kKeysetTypeUrl[] = "type.googleapis.com/google.crypto.tink.Keyset";

absl::StatusOr<KeysetHandle> ParseKeysetFromJsonProtoKeysetFormatWithOptional(
    absl::string_view serialized_keyset,
    std::optional<SecretKeyAccessToken> token) {
  ParseOptions parse_options;
  std::string binary_keyset;
  absl::Status status =
      JsonToBinaryString(internal::GetTinkTypeResolver(), kKeysetTypeUrl,
                         serialized_keyset, &binary_keyset, parse_options);
  if (!status.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid JSON Keyset");
  }

  if (token.has_value()) {
    return ParseKeysetFromProtoKeysetFormat(binary_keyset, *token);
  } else {
    return ParseKeysetWithoutSecretFromProtoKeysetFormat(binary_keyset);
  }
}

absl::Status ValidateNoSecret(const google::crypto::tink::Keyset& keyset) {
  for (const google::crypto::tink::Keyset::Key& key : keyset.key()) {
    if (key.key_data().key_material_type() ==
            google::crypto::tink::KeyData::UNKNOWN_KEYMATERIAL ||
        key.key_data().key_material_type() ==
            google::crypto::tink::KeyData::SYMMETRIC ||
        key.key_data().key_material_type() ==
            google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE) {
      return absl::Status(
          absl::StatusCode::kFailedPrecondition,
          "Cannot create KeysetHandle with secret key material from "
          "potentially unencrypted source.");
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> SerializeKeysetToJsonProtoKeysetFormatWithOptional(
    const KeysetHandle& keyset_handle,
    std::optional<SecretKeyAccessToken> token) {
  const google::crypto::tink::Keyset& keyset =
      CleartextKeysetHandle::GetKeyset(keyset_handle);
  if (!token.has_value()) {
    absl::Status status = ValidateNoSecret(keyset);
    if (!status.ok()) {
      return status;
    }
  }

  SecretBuffer result(keyset.ByteSizeLong());
  bool serialized = internal::CallWithCoreDumpProtection(
      [&]() { return keyset.SerializeToArray(result.data(), result.size()); });
  if (!serialized) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize keyset");
  }

  PrintOptions options;
  std::string output;
  absl::Status status =
      BinaryToJsonString(internal::GetTinkTypeResolver(), kKeysetTypeUrl,
                         std::string(result.AsStringView()), &output, options);
  if (!status.ok()) {
    return status;
  }

  return output;
}
}  // namespace

absl::StatusOr<KeysetHandle> ParseKeysetFromJsonProtoKeysetFormat(
    absl::string_view serialized_keyset, SecretKeyAccessToken token) {
  return ParseKeysetFromJsonProtoKeysetFormatWithOptional(serialized_keyset,
                                                          token);
}

absl::StatusOr<KeysetHandle> ParseKeysetWithoutSecretFromJsonProtoKeysetFormat(
    absl::string_view serialized_keyset) {
  return ParseKeysetFromJsonProtoKeysetFormatWithOptional(serialized_keyset,
                                                          absl::nullopt);
}

absl::StatusOr<SecretData> SerializeKeysetToJsonProtoKeysetFormat(
    const KeysetHandle& keyset_handle, SecretKeyAccessToken token) {
  absl::StatusOr<std::string> result =
      SerializeKeysetToJsonProtoKeysetFormatWithOptional(keyset_handle, token);
  if (!result.ok()) {
    return result.status();
  }
  return util::SecretDataFromStringView(result.value());
}

absl::StatusOr<std::string> SerializeKeysetWithoutSecretToJsonProtoKeysetFormat(
    const KeysetHandle& keyset_handle) {
  return SerializeKeysetToJsonProtoKeysetFormatWithOptional(keyset_handle,
                                                            absl::nullopt);
}

}  // namespace tink
}  // namespace crypto
