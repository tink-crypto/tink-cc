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

#include "walkthrough/write_keyset.h"

// [START tink_walkthrough_write_keyset]
#include <memory>
#include <ostream>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/aead.h"
#include "tink/json/json_keyset_writer.h"
#include "tink/keyset_handle.h"

namespace tink_walkthrough {

using ::crypto::tink::JsonKeysetWriter;

// Writes a `keyset` to `output_stream` in JSON format; the keyset is encrypted
// with `keyset_encryption_aead`.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
//  - Get the keyset encryption AEAD for a key URI with KmsClient::GetAead.
//  - Create a keyset and obtain a KeysetHandle to it.
absl::Status WriteEncryptedKeyset(
    const crypto::tink::KeysetHandle& keyset,
    std::unique_ptr<std::ostream> output_stream,
    const crypto::tink::Aead& keyset_encryption_aead) {
  // Create a writer that will write the keyset to output_stream as JSON.
  absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(output_stream));
  if (!writer.ok()) return writer.status();
  return keyset.Write(writer->get(), keyset_encryption_aead);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_write_keyset]
