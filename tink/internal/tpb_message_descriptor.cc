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

#include "tink/internal/tpb_message_descriptor.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Status TpbMessageDescriptor::AddUint32(int tag) {
  if (!types_.emplace(tag, Type::kUint32).second) {
    return absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
  }
  return absl::OkStatus();
}

absl::Status TpbMessageDescriptor::AddBytes(int tag) {
  if (!types_.emplace(tag, Type::kBytes).second) {
    return absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
  }
  return absl::OkStatus();
}

absl::Status TpbMessageDescriptor::AddMessage(
    int tag, const TpbMessageDescriptor& descriptor) {
  if (!types_.emplace(tag, Type::kMessage).second) {
    return absl::InvalidArgumentError(
        absl::StrCat("Tag ", tag, " already exists"));
  }
  message_descriptors_[tag] =
      std::make_shared<TpbMessageDescriptor>(descriptor);
  return absl::OkStatus();
}

const TpbMessageDescriptor* TpbMessageDescriptor::GetMessage(
    int tag) const {
  auto it = message_descriptors_.find(tag);
  if (it == message_descriptors_.end()) {
    return nullptr;
  }
  return it->second.get();
}

absl::StatusOr<TpbMessageDescriptor::Type> TpbMessageDescriptor::GetType(
    int tag) const {
  auto it = types_.find(tag);
  if (it == types_.end()) {
    return absl::InvalidArgumentError(absl::StrCat("Tag ", tag, " not found"));
  }
  return it->second;
}

bool operator==(const TpbMessageDescriptor& lhs,
                const TpbMessageDescriptor& rhs) {
  if (lhs.types_ != rhs.types_) return false;
  return lhs.message_descriptors_.size() == rhs.message_descriptors_.size() &&
         std::equal(lhs.message_descriptors_.begin(),
                    lhs.message_descriptors_.end(),
                    rhs.message_descriptors_.begin(), [](auto l, auto r) {
                      return l.first == r.first && *l.second == *r.second;
                    });
}

bool operator!=(const TpbMessageDescriptor& lhs,
                const TpbMessageDescriptor& rhs) {
  return !(lhs == rhs);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
