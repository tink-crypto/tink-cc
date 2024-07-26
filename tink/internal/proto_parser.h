// Copyright 2024 Google LLC
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

#ifndef TINK_INTERNAL_PROTO_PARSER_H_
#define TINK_INTERNAL_PROTO_PARSER_H_

#include <cstdint>
#include <string>
#include <utility>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

enum class ProtoFieldType { kUint32, kBytesString, kBytesSecretData };

// A helper class to parse a serialized proto message.  Suppose for example we
// have the a proto such as:
//
// message AesGcmKey {
//   uint32 version_number = 1;
//   uint32 key_size = 2;
//   bytes key = 3;
// }
//
// We could parse it with the following code:
//
// constexpr int32_t kVersionNumberTag = 1;
// constexpr int32_t kKeySizeTag = 2;
// constexpr int32_t kKeyTag = 3;
// SecretData key;
// uint32_t version_number = 0;
// uint32_t key_size = 0;
// absl::Status s = ProtoParser()
//     .AddUint32Field(kVersionNumberTag, version_number)
//     .AddUint32Field(kKeySizeTag, key_size)
//     .AddBytesSecretDataField(kKeyTag, key, secret_key_access_token)
//     .Parse(serialized_proto);
// if (!s.ok()) return s;
//
// This will parse the serialized proto and set version_number, key_size, and
// key accordingly.
//
// All variables used need to be initialized to their default value.
// If the return value of Parse is an error, variables are in an unspecified
// state. Parse must not be called twice. Fields can be added in any order.
class ProtoParser {
 public:
  ProtoParser() = default;
  // Not movable or copyable.
  ProtoParser(const ProtoParser&) = delete;
  ProtoParser& operator=(const ProtoParser&) = delete;

  ProtoParser& AddUint32Field(int tag, uint32_t& value);
  ProtoParser& AddBytesStringField(int tag, std::string& value);
  ProtoParser& AddBytesSecretDataField(
      int tag, crypto::tink::util::SecretData& value,
      crypto::tink::SecretKeyAccessToken token);

  absl::Status Parse(absl::string_view input);

 private:
  struct Field {
    ProtoFieldType type;

    // field.value.index() == static_cast<int>(field.type)
    absl::variant<uint32_t*, std::string*, crypto::tink::util::SecretData*>
        value;
  };

  // Wiretype::kVarint
  absl::Status ConsumeVarintWithTag(absl::string_view& serialized, int tag);
  absl::Status ConsumeUint32WithField(absl::string_view& serialized,
                                      const Field& field);

  // Wiretype::kLengthDelimited
  absl::Status ConsumeLengthDelimitedWithTag(absl::string_view& serialized,
                                             int tag);
  absl::Status ConsumeBytesToStringWithField(absl::string_view& serialized,
                                             const Field& field);
  absl::Status ConsumeBytesToSecretDataWithField(absl::string_view& serialized,
                                                 const Field& field);
  absl::StatusOr<absl::string_view> ConsumeBytesReturnStringView(
      absl::string_view& serialized);

  // Overwrites all fields to their default value (in case they are not
  // explicitly set by the input)
  void ClearAllFields();

  absl::Status permanent_error_;

  absl::btree_map<int, Field> fields_;
};

// Exposed for testing only
absl::StatusOr<uint64_t> ConsumeVarintIntoUint64(absl::string_view& serialized);

// Exposed for testing only
absl::StatusOr<uint32_t> ConsumeVarintIntoUint32(absl::string_view& serialized);

// See https://protobuf.dev/programming-guides/encoding/#structure
// and
// https://github.com/protocolbuffers/protobuf/blob/main/src/google/protobuf/wire_format_lite.h
// for the names.
// Exposed for testing only
enum class WireType : uint8_t {
  kVarint = 0,
  kFixed64 = 1,
  kLengthDelimited = 2,
  kStartGroup = 3,
  kEndGroup = 4,
  kFixed32 = 5,
};

// Exposed for testing only
absl::StatusOr<std::pair<WireType, int>> ConsumeIntoWireTypeAndTag(
    absl::string_view& serialized);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_H_
