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

#ifndef TINK_INTERNAL_TPB_MESSAGE_DESCRIPTOR_H_
#define TINK_INTERNAL_TPB_MESSAGE_DESCRIPTOR_H_

#include <memory>

#include "absl/container/btree_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// A TinkProtoBuf message descriptor. This describes the format of a message.
// (i.e., it describes what's usually in a .proto file).
class TpbMessageDescriptor {
 public:
  TpbMessageDescriptor() = default;
  // Movable and copyable.
  TpbMessageDescriptor(const TpbMessageDescriptor&) = default;
  TpbMessageDescriptor(TpbMessageDescriptor&&) noexcept = default;
  TpbMessageDescriptor& operator=(const TpbMessageDescriptor&) = default;
  TpbMessageDescriptor& operator=(TpbMessageDescriptor&&) noexcept = default;

  // The type of a field:
  // https://protobuf.dev/reference/protobuf/proto3-spec/#fields
  enum class Type { kUint32, kBytes, kMessage };

  // Adds a uint32 field with the given tag.
  absl::Status AddUint32(int tag);

  // Adds a bytes field with the given tag.
  absl::Status AddBytes(int tag);

  // Adds a message field with the given tag.
  // Note: recursive messages are not supported.
  absl::Status AddMessage(int tag, const TpbMessageDescriptor& descriptor);
  const TpbMessageDescriptor* GetMessage(int tag) const;

  // Returns the type of the field with the given tag.
  absl::StatusOr<Type> GetType(int tag) const;

  friend bool operator==(const TpbMessageDescriptor& lhs,
                         const TpbMessageDescriptor& rhs);
  friend bool operator!=(const TpbMessageDescriptor& lhs,
                         const TpbMessageDescriptor& rhs);

 private:
  absl::btree_map<int, Type> types_;
  // We cannot have a map <int, TpbMessageDescriptor> because
  // TpbMessageDescriptor is incomplete at this point. We hence use shared_ptr
  // instead (with unique_ptr we would have to manually write the copy
  // constructor of TpbMessageDescriptor).
  absl::btree_map<int, std::shared_ptr<TpbMessageDescriptor>>
      message_descriptors_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TPB_MESSAGE_DESCRIPTOR_H_
