// Copyright 2017 Google Inc.
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

#include "tink/cleartext_keyset_handle.h"

#include <istream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/errors.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {

// static
absl::StatusOr<std::unique_ptr<KeysetHandle>> CleartextKeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader,
    absl::flat_hash_map<std::string, std::string> monitoring_annotations) {
  absl::StatusOr<std::unique_ptr<Keyset>> keyset_result = reader->Read();
  if (!keyset_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Error reading keyset data: %s",
                     keyset_result.status().message());
  }
  absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandle::GetEntriesFromKeyset(**keyset_result);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != (*keyset_result)->key_size()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(util::SecretProto<Keyset>(**keyset_result), *entries,
                       std::move(monitoring_annotations)));
  return std::move(handle);
}

// static
absl::Status CleartextKeysetHandle::Write(KeysetWriter* writer,
                                          const KeysetHandle& keyset_handle) {
  if (!writer) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Error KeysetWriter cannot be null");
  }
  return writer->Write(keyset_handle.get_keyset());
}

// static
std::unique_ptr<KeysetHandle> CleartextKeysetHandle::GetKeysetHandle(
    const Keyset& keyset) {
  std::unique_ptr<KeysetHandle> handle =
      absl::WrapUnique(new KeysetHandle(util::SecretProto<Keyset>(keyset)));
  return handle;
}

// static
const Keyset& CleartextKeysetHandle::GetKeyset(
    const KeysetHandle& keyset_handle) {
  return keyset_handle.get_keyset();
}

}  // namespace tink
}  // namespace crypto
