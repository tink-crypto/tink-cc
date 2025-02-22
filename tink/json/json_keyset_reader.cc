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

#include "tink/json/json_keyset_reader.h"

#include <iostream>
#include <istream>
#include <iterator>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/json/json.h"
#include "tink/json/internal/tink_type_resolver.h"
#include "tink/keyset_reader.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;
using ::google::protobuf::json::ParseOptions;

namespace {

const char kKeysetTypeUrl[] = "type.googleapis.com/google.crypto.tink.Keyset";
const char kEncryptedKeysetTypeUrl[] =
    "type.googleapis.com/google.crypto.tink.EncryptedKeyset";

}  // namespace

//  static
util::StatusOr<std::unique_ptr<KeysetReader>> JsonKeysetReader::New(
    std::unique_ptr<std::istream> keyset_stream) {
  if (keyset_stream == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "keyset_stream must be non-null.");
  }
  return absl::WrapUnique(new JsonKeysetReader(std::move(keyset_stream)));
}

//  static
util::StatusOr<std::unique_ptr<KeysetReader>> JsonKeysetReader::New(
    absl::string_view serialized_keyset) {
  return absl::WrapUnique(new JsonKeysetReader(serialized_keyset));
}

util::StatusOr<std::unique_ptr<Keyset>> JsonKeysetReader::Read() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream =
        std::string(std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }

  ParseOptions parse_options;
  std::string binary_keyset;
  absl::Status status =
      JsonToBinaryString(internal::GetTinkTypeResolver(), kKeysetTypeUrl,
                         *serialized_keyset, &binary_keyset, parse_options);
  if (!status.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid JSON Keyset");
  }
  auto keyset = absl::make_unique<Keyset>();
  if (!keyset->ParseFromString(binary_keyset)) {
    return util::Status(absl::StatusCode::kInternal,
                        "internal error parsing keyset");
  };
  return std::move(keyset);
}

util::StatusOr<std::unique_ptr<EncryptedKeyset>>
JsonKeysetReader::ReadEncrypted() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream =
        std::string(std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }

  ParseOptions parse_options;
  std::string binary_encrypted_keyset;
  absl::Status status = JsonToBinaryString(
      internal::GetTinkTypeResolver(), kEncryptedKeysetTypeUrl,
      *serialized_keyset, &binary_encrypted_keyset, parse_options);
  if (!status.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  auto encrypted_keyset = absl::make_unique<EncryptedKeyset>();
  if (!encrypted_keyset->ParseFromString(binary_encrypted_keyset)) {
    return util::Status(absl::StatusCode::kInternal,
                        "internal error parsing encrypted_keyset");
  };
  return std::move(encrypted_keyset);
}

}  // namespace tink
}  // namespace crypto
