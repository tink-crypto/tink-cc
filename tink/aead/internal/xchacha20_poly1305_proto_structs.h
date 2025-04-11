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

#ifndef TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_STRUCTS_H_
#define TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_STRUCTS_H_

#include <cstdint>

#include "absl/base/no_destructor.h"
#include "tink/internal/proto_parser.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

struct XChaCha20Poly1305KeyFormatStruct {
  uint32_t version = 0;

  inline static const crypto::tink::internal::ProtoParser<
      XChaCha20Poly1305KeyFormatStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<XChaCha20Poly1305KeyFormatStruct>>
        parser(
            crypto::tink::internal::ProtoParserBuilder<
                XChaCha20Poly1305KeyFormatStruct>()
                .AddUint32Field(1, &XChaCha20Poly1305KeyFormatStruct::version)
                .BuildOrDie());
    return *parser;
  }
};

struct XChaCha20Poly1305KeyStruct {
  uint32_t version = 0;
  SecretData key_value = {};

  inline static const crypto::tink::internal::ProtoParser<
      XChaCha20Poly1305KeyStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<XChaCha20Poly1305KeyStruct>>
        parser(crypto::tink::internal::ProtoParserBuilder<
                   XChaCha20Poly1305KeyStruct>()
                   .AddUint32Field(1, &XChaCha20Poly1305KeyStruct::version)
                   .AddBytesSecretDataField(
                       3, &XChaCha20Poly1305KeyStruct::key_value)
                   .BuildOrDie());
    return *parser;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_XCHACHA20_POLY1305_PROTO_STRUCTS_H_
