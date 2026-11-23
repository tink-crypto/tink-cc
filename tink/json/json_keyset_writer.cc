// Copyright 2018 Google Inc.
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

#include "tink/json/json_keyset_writer.h"

#include <memory>
#include <ostream>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/json/json.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/internal/secret_proto_util.h"
#include "tink/json/internal/tink_type_resolver.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {


using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;
using ::google::protobuf::json::BinaryToJsonStream;
using ::google::protobuf::json::BinaryToJsonString;
using ::google::protobuf::json::PrintOptions;

namespace {

const char kKeysetTypeUrl[] = "type.googleapis.com/google.crypto.tink.Keyset";
const char kEncryptedKeysetTypeUrl[] =
    "type.googleapis.com/google.crypto.tink.EncryptedKeyset";

absl::StatusOr<std::string> ToJsonString(const Keyset& keyset) {
  ABSL_ASSIGN_OR_RETURN(internal::SecretBuffer serialized_keyset,
                        internal::SerializeProtoAsSecretBuffer(keyset));
  PrintOptions options;
  std::string output;
  ABSL_RETURN_IF_ERROR(internal::CallWithCoreDumpProtection([&]() {
    google::protobuf::io::ArrayInputStream input_stream(
        serialized_keyset.data(), static_cast<int>(serialized_keyset.size()));
    google::protobuf::io::StringOutputStream output_stream(&output);
    return BinaryToJsonStream(internal::GetTinkTypeResolver(), kKeysetTypeUrl,
                              &input_stream, &output_stream, options);
  }));
  return output;
}

absl::StatusOr<std::string> ToJsonString(const EncryptedKeyset& keyset) {
  PrintOptions options;
  std::string output;
  absl::Status status = BinaryToJsonString(
      internal::GetTinkTypeResolver(), kEncryptedKeysetTypeUrl,
      keyset.SerializeAsString(), &output, options);
  if (!status.ok()) {
    return status;
  }
  return output;
}

absl::Status WriteData(absl::string_view data, std::ostream* destination) {
  (*destination) << data;
  if (destination->fail()) {
    return absl::Status(absl::StatusCode::kUnknown,
                        "Error writing to the destination stream.");
  }
  return absl::OkStatus();
}

}  // anonymous namespace


//  static
absl::StatusOr<std::unique_ptr<JsonKeysetWriter>> JsonKeysetWriter::New(
    std::unique_ptr<std::ostream> destination_stream) {
  if (destination_stream == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "destination_stream must be non-null.");
  }
  std::unique_ptr<JsonKeysetWriter> writer(
      new JsonKeysetWriter(std::move(destination_stream)));
  return std::move(writer);
}

absl::Status JsonKeysetWriter::Write(const Keyset& keyset) {
  auto json_string_result = ToJsonString(keyset);
  if (!json_string_result.ok()) return json_string_result.status();
  return WriteData(json_string_result.value(), destination_stream_.get());
}

absl::Status JsonKeysetWriter::Write(const EncryptedKeyset& encrypted_keyset) {
  auto json_string_result = ToJsonString(encrypted_keyset);
  if (!json_string_result.ok()) return json_string_result.status();
  return WriteData(json_string_result.value(), destination_stream_.get());
}

}  // namespace tink
}  // namespace crypto
