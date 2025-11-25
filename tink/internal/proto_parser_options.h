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

#ifndef TINK_INTERNAL_PROTO_PARSER_OPTIONS_H_
#define TINK_INTERNAL_PROTO_PARSER_OPTIONS_H_

namespace crypto {
namespace tink {
namespace internal {

// Options for proto fields.
//
// WARNING: This isn't fully implemented yet for all fields.
//
// [1] https://protobuf.dev/editions/features/#field_presence.
enum class ProtoFieldOptions {
  // Does not track field presence, serializes the field only if the value
  // is not the default. This is equivalent to Protobufs `IMPLICIT` [1].
  // NOTE:
  //  - Message fields do not support this option.
  //  - `IMPLICIT` scalar fields do no support custom default values.
  kImplicit = 0,
  // Tracks field presence. This means that after a call to "set_field" the
  // field will be serialized, even if the value equals the default. This is
  // equivalent to Protobufs `EXPLICIT` [1].
  kExplicit = 1,
  // Consider the field to be always present, and thus serialize it even if
  // the value is the default.
  kAlwaysPresent = 2,
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OPTIONS_H_
