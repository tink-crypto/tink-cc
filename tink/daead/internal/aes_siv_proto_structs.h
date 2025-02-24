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

#ifndef TINK_DAEAD_INTERNAL_AES_SIV_PROTO_STRUCTS_H_
#define TINK_DAEAD_INTERNAL_AES_SIV_PROTO_STRUCTS_H_

#include <cstdint>

#include "absl/base/no_destructor.h"
#include "tink/internal/proto_parser.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;

// Proto message com.google.crypto.tink.AesSivKeyFormat.
struct AesSivKeyFormatStruct {
  uint32_t key_size;
  uint32_t version;

  inline static const ProtoParser<AesSivKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesSivKeyFormatStruct>> parser(
        ProtoParserBuilder<AesSivKeyFormatStruct>()
            .AddUint32Field(1, &AesSivKeyFormatStruct::key_size)
            .AddUint32Field(2, &AesSivKeyFormatStruct::version)
            .BuildOrDie());
    return *parser;
  }
};

// Proto message com.google.crypto.tink.AesSivKey.
struct AesSivKeyStruct {
  uint32_t version;
  util::SecretData key_value;

  inline static const ProtoParser<AesSivKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesSivKeyStruct>> parser(
        ProtoParserBuilder<AesSivKeyStruct>()
            .AddUint32Field(1, &AesSivKeyStruct::version)
            .AddBytesSecretDataField(2, &AesSivKeyStruct::key_value)
            .BuildOrDie());
    return *parser;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_INTERNAL_AES_SIV_PROTO_STRUCTS_H_
