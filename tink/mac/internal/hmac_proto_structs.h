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

#ifndef TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
#define TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_

#include <cstdint>

#include "absl/base/no_destructor.h"
#include "tink/internal/common_proto_enums.h"
#include "tink/internal/proto_parser.h"

namespace crypto {
namespace tink {
namespace internal {

struct HmacParamsStruct {
  HashTypeEnum hash = HashTypeEnum::kUnknownHash;
  uint32_t tag_size = 0;

  static crypto::tink::internal::ProtoParser<HmacParamsStruct> CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<HmacParamsStruct>()
        .AddEnumField(1, &HmacParamsStruct::hash, &HashTypeEnumIsValid)
        .AddUint32Field(2, &HmacParamsStruct::tag_size)
        .BuildOrDie();
  }

  static const crypto::tink::internal::ProtoParser<HmacParamsStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<HmacParamsStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct HmacKeyFormatStruct {
  HmacParamsStruct params = {};
  uint32_t key_size = 0;
  uint32_t version = 0;

  static crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>
  CreateParser() {
    return crypto::tink::internal::ProtoParserBuilder<HmacKeyFormatStruct>()
        .AddMessageField(1, &HmacKeyFormatStruct::params,
                         HmacParamsStruct::CreateParser())
        .AddUint32Field(2, &HmacKeyFormatStruct::key_size)
        .AddUint32Field(3, &HmacKeyFormatStruct::version)
        .BuildOrDie();
  }

  static const crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>&
  GetParser() {
    static const absl::NoDestructor<
        crypto::tink::internal::ProtoParser<HmacKeyFormatStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_HMAC_PROTO_STRUCTS_H_
