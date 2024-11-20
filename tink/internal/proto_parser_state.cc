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

#include "tink/internal/proto_parser_state.h"

#include <cstddef>

#include "absl/crc/crc32c.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_parsing {

util::SecretValue<absl::crc32c_t> ParsingState::AdvanceAndGetCrc(
    size_t length) {
  util::SecretValue<absl::crc32c_t> result;
  CallWithCoreDumpProtection([&]() {
    result.value() =
        absl::ComputeCrc32c(remaining_view_to_parse_.substr(0, length));
    if (crc_to_update_) {
      *crc_to_update_ =
          absl::ConcatCrc32c(*crc_to_update_, result.value(), length);
    };
  });
  remaining_view_to_parse_.remove_prefix(length);
  return result;
}

void SerializationState::AdvanceWithCrc(size_t length, absl::crc32c_t crc) {
  output_buffer_.remove_prefix(length);
  if (crc_to_update_ != nullptr) {
    *crc_to_update_ = absl::ConcatCrc32c(*crc_to_update_, crc, length);
  }
}

}  // namespace proto_parsing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
