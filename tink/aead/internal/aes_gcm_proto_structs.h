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

#ifndef TINK_AEAD_INTERNAL_AES_GCM_PROTO_STRUCTS_H_
#define TINK_AEAD_INTERNAL_AES_GCM_PROTO_STRUCTS_H_

#include <cstdint>

#include "absl/base/no_destructor.h"
#include "tink/internal/proto_parser.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::internal::ProtoParser;
using ::crypto::tink::internal::ProtoParserBuilder;
using ::crypto::tink::util::SecretData;

struct AesGcmKeyFormatStruct {
  uint32_t key_size = 0;
  uint32_t version = 0;

  inline static const ProtoParser<AesGcmKeyFormatStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesGcmKeyFormatStruct>> parser{
        ProtoParserBuilder<AesGcmKeyFormatStruct>()
            .AddUint32Field(2, &AesGcmKeyFormatStruct::key_size)
            .AddUint32Field(3, &AesGcmKeyFormatStruct::version)
            .BuildOrDie()};
    return *parser;
  }
};

struct AesGcmKeyStruct {
  uint32_t version = 0;
  SecretData key_value = {};

  inline static const ProtoParser<AesGcmKeyStruct>& GetParser() {
    static const absl::NoDestructor<ProtoParser<AesGcmKeyStruct>> parser{
        ProtoParserBuilder<AesGcmKeyStruct>()
            .AddUint32Field(1, &AesGcmKeyStruct::version)
            .AddBytesSecretDataField(3, &AesGcmKeyStruct::key_value)
            .BuildOrDie()};
    return *parser;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_GCM_PROTO_STRUCTS_H_
