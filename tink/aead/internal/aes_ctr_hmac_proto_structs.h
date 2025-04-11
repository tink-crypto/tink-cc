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

#ifndef TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_
#define TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_

#include <cstdint>

#include "tink/internal/proto_parser.h"
#include "tink/mac/internal/hmac_proto_structs.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

struct AesCtrParamsStruct {
  uint32_t iv_size = 0;

  static crypto::tink::internal::ProtoParser<AesCtrParamsStruct>
  CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<AesCtrParamsStruct>()
        .AddUint32Field(1, &AesCtrParamsStruct::iv_size)
        .BuildOrDie();
  }
};

struct AesCtrKeyFormatStruct {
  AesCtrParamsStruct params = {};
  uint32_t key_size = 0;
};

struct AesCtrHmacAeadKeyFormatStruct {
  AesCtrKeyFormatStruct aes_ctr_key_format = {};
  HmacKeyFormatStruct hmac_key_format = {};

  static const crypto::tink::internal::ProtoParser<
      AesCtrHmacAeadKeyFormatStruct>&
  GetParser();
};

struct AesCtrKeyStruct {
  uint32_t version = 0;
  AesCtrParamsStruct params = {};
  SecretData key_value = {};
};

struct HmacKeyStruct {
  uint32_t version = 0;
  HmacParamsStruct params = {};
  SecretData key_value = {};
};

struct AesCtrHmacAeadKeyStruct {
  uint32_t version = 0;
  AesCtrKeyStruct aes_ctr_key = {};
  HmacKeyStruct hmac_key = {};

  static const crypto::tink::internal::ProtoParser<AesCtrHmacAeadKeyStruct>&
  GetParser();
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AES_CTR_HMAC_PROTO_STRUCTS_H_
