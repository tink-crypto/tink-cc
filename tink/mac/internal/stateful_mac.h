// Copyright 2019 Google LLC
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

// The interface for stateful message authentication codes.
//
// WARNING: implementations of this interface are thread-compatible,
// but not thread-safe. Therefore, a streaming mac implemented with this
// interface is required to additionally enforce thread safety.
//
// This interface supports the implementation of both streaming
// and non-streaming MACs. It does not enforce thread-safety in order to avoid
// an unnecessary performance overhead for non-streaming MAC implementations.

#ifndef TINK_MAC_INTERNAL_STATEFUL_MAC_H_
#define TINK_MAC_INTERNAL_STATEFUL_MAC_H_

#include <memory>
#include <string>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class StatefulMac {
 public:
  StatefulMac() = default;
  virtual ~StatefulMac() = default;

  virtual absl::Status Update(absl::string_view data) = 0;

  virtual absl::StatusOr<SecretData> FinalizeAsSecretData() = 0;
};

class StatefulMacFactory {
 public:
  virtual ~StatefulMacFactory() = default;

  virtual absl::StatusOr<std::unique_ptr<StatefulMac>> Create() const = 0;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_INTERNAL_STATEFUL_MAC_H_
