// Copyright 2021 Google LLC
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

#include "tink/jwt/internal/json_util.h"

#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/json/json.h"
#include "google/protobuf/util/json_util.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::google::protobuf::ListValue;
using ::google::protobuf::Struct;
using ::google::protobuf::util::JsonParseOptions;
using ::google::protobuf::util::JsonStringToMessage;
using ::google::protobuf::util::MessageToJsonString;

absl::StatusOr<Struct> JsonStringToProtoStruct(absl::string_view json_string) {
  Struct proto;
  JsonParseOptions json_parse_options;
  absl::Status status =
      JsonStringToMessage(json_string, &proto, json_parse_options);
  if (!status.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  return proto;
}

absl::StatusOr<ListValue> JsonStringToProtoList(absl::string_view json_string) {
  ListValue proto;
  JsonParseOptions json_parse_options;
  absl::Status status =
      JsonStringToMessage(json_string, &proto, json_parse_options);
  if (!status.ok()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "invalid JSON");
  }
  return proto;
}

absl::StatusOr<std::string> ProtoStructToJsonString(const Struct& proto) {
  std::string output;
  absl::Status status = MessageToJsonString(proto, &output);
  if (!status.ok()) {
    return status;
  }
  return output;
}

absl::StatusOr<std::string> ProtoListToJsonString(const ListValue& proto) {
  std::string output;
  absl::Status status = MessageToJsonString(proto, &output);
  if (!status.ok()) {
    return status;
  }
  return output;
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
