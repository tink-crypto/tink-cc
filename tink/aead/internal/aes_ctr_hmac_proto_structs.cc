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

#include "tink/aead/internal/aes_ctr_hmac_proto_structs.h"

#include "absl/base/no_destructor.h"
#include "tink/internal/proto_parser.h"
#include "tink/mac/internal/hmac_proto_structs.h"

namespace crypto {
namespace tink {
namespace internal {

const internal::ProtoParser<AesCtrHmacAeadKeyFormatStruct>&
AesCtrHmacAeadKeyFormatStruct::GetParser() {
  static const absl::NoDestructor<
      crypto::tink::internal::ProtoParser<AesCtrHmacAeadKeyFormatStruct>>
      parser{crypto::tink::internal::ProtoParserBuilder<
                 AesCtrHmacAeadKeyFormatStruct>()
                 .AddMessageField(
                     1, &AesCtrHmacAeadKeyFormatStruct::aes_ctr_key_format,
                     crypto::tink::internal::ProtoParserBuilder<
                         AesCtrKeyFormatStruct>()
                         .AddMessageField(1, &AesCtrKeyFormatStruct::params,
                                          AesCtrParamsStruct::CreateParser())
                         .AddUint32Field(2, &AesCtrKeyFormatStruct::key_size)
                         .BuildOrDie())
                 .AddMessageField(
                     2, &AesCtrHmacAeadKeyFormatStruct::hmac_key_format,
                     HmacKeyFormatStruct::CreateParser())
                 .BuildOrDie()};
  return *parser;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
