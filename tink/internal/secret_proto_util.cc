// Copyright 2026 Google LLC
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

#include "tink/internal/secret_proto_util.h"

#include <cstddef>
#include <limits>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/secret_buffer.h"
#include "tink/util/protobuf_helper.h"

namespace crypto {
namespace tink {
namespace internal {

absl::StatusOr<SecretBuffer> SerializeProtoAsSecretBuffer(
    const portable_proto::MessageLite& proto) {
  size_t size =
      CallWithCoreDumpProtection([&]() { return proto.ByteSizeLong(); });
  if (size > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Proto too large to serialize.");
  }
  SecretBuffer buffer(size);
  bool serialized = CallWithCoreDumpProtection([&]() {
    return proto.SerializeToArray(buffer.data(), static_cast<int>(size));
  });
  if (!serialized) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Failed to serialize proto.");
  }
  return buffer;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
