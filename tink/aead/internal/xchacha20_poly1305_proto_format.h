// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_FORMAT_H_
#define TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_FORMAT_H_

#include <array>
#include <cstddef>
#include <cstdint>

#include "tink/internal/proto_parser_fields.h"
#include "tink/internal/proto_parser_message.h"

namespace crypto {
namespace tink {
namespace internal {

class XChaCha20Poly1305KeyFormatTP : public proto_parsing::Message {
 public:
  XChaCha20Poly1305KeyFormatTP() = default;

  uint32_t version() const { return version_.value(); }
  void set_version(uint32_t value) { version_.set_value(value); }

  // This is OK because this class doesn't contain secret data.
  using Message::SerializeAsString;

 private:
  size_t num_fields() const override { return 1; }
  const proto_parsing::Field* field(int i) const override {
    return std::array<const proto_parsing::Field*, 1>{&version_}[i];
  }

  proto_parsing::Uint32Field version_{1, ProtoFieldOptions::kImplicit};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_FORMAT_H_
