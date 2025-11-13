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

enum class ProtoFieldOptions {
  // Do not serialize in case the value of the field is the default.
  kNone = 0,
  // Consider the field to be always present, and thus serialize it even if
  // the value is the default.
  kAlwaysPresent = 1,
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_PARSER_OPTIONS_H_
