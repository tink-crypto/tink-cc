// Copyright 2022 Google LLC
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

#include "tink/proto_keyset_format.h"

#include <ios>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::internal::SecretBuffer;

absl::StatusOr<KeysetHandle> ParseKeysetFromProtoKeysetFormat(
    absl::string_view serialized_keyset, SecretKeyAccessToken token) {
  util::SecretProto<google::crypto::tink::Keyset> keyset_proto;
  bool parsed = internal::CallWithCoreDumpProtection(
      [&]() { return keyset_proto->ParseFromString(serialized_keyset); });
  if (!parsed) {
    return absl::Status(absl::StatusCode::kInternal, "Failed to parse keyset");
  }
  absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandle::GetEntriesFromKeyset(*keyset_proto);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != keyset_proto->key_size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return KeysetHandle(std::move(keyset_proto), *std::move(entries));
}

absl::StatusOr<SecretData> SerializeKeysetToProtoKeysetFormat(
    const KeysetHandle& keyset_handle, SecretKeyAccessToken token) {
  const google::crypto::tink::Keyset& keyset =
      CleartextKeysetHandle::GetKeyset(keyset_handle);
  SecretBuffer result(keyset.ByteSizeLong());
  bool serialized = internal::CallWithCoreDumpProtection(
      [&]() { return keyset.SerializeToArray(result.data(), result.size()); });
  if (!serialized) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize keyset");
  }
  return util::internal::AsSecretData(std::move(result));
}

absl::StatusOr<KeysetHandle> ParseKeysetWithoutSecretFromProtoKeysetFormat(
    absl::string_view serialized_keyset) {
  std::string keyset_copy = std::string(serialized_keyset);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> result =
      KeysetHandle::ReadNoSecret(keyset_copy);
  if (!result.ok()) {
    return result.status();
  }
  return std::move(**result);
}

absl::StatusOr<std::string> SerializeKeysetWithoutSecretToProtoKeysetFormat(
    const KeysetHandle& keyset_handle) {
  std::stringbuf string_buf(std::ios_base::out);
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> keyset_writer =
      BinaryKeysetWriter::New(std::make_unique<std::ostream>(&string_buf));
  if (!keyset_writer.ok()) {
    return keyset_writer.status();
  }
  absl::Status status = keyset_handle.WriteNoSecret(keyset_writer->get());
  if (!status.ok()) {
    return status;
  }
  return string_buf.str();
}

absl::StatusOr<KeysetHandle> ParseKeysetFromEncryptedKeysetFormat(
    absl::string_view encrypted_keyset, const Aead& keyset_encryption_aead,
    absl::string_view associated_data) {
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(encrypted_keyset);
  if (!reader.ok()) {
    return reader.status();
  }
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::ReadWithAssociatedData(
          std::move(*reader), keyset_encryption_aead, associated_data);
  if (!handle.ok()) {
    return handle.status();
  }
  return std::move(**handle);
}

absl::StatusOr<std::string> SerializeKeysetToEncryptedKeysetFormat(
    const KeysetHandle& keyset_handle, const Aead& keyset_encryption_aead,
    absl::string_view associated_data) {
  std::stringbuf encrypted_keyset;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(
          absl::make_unique<std::ostream>(&encrypted_keyset));
  if (!writer.ok()) {
    return writer.status();
  }
  absl::Status status = keyset_handle.WriteWithAssociatedData(
      writer->get(), keyset_encryption_aead, associated_data);
  if (!status.ok()) {
    return status;
  }
  return encrypted_keyset.str();
}

}  // namespace tink
}  // namespace crypto
