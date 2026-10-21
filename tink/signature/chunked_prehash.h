// Copyright 2026 Google LLC
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

#ifndef TINK_SIGNATURE_CHUNKED_PREHASH_H_
#define TINK_SIGNATURE_CHUNKED_PREHASH_H_

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {

// Interface for a single chunked precomputed hash value computation.
//
// WARNING: Although implementations of this interface are thread-compatible,
// they are not thread-safe.  Thread-safety must be enforced by the caller.
class ChunkedPrehashComputation {
 public:
  // Incrementally processes input `data` to update the internal state of the
  // hash computation.  Requires exclusive access.
  //
  // Note that the following two update sequences are equivalent (i.e.,
  // arbitrary slicing of the input data is allowed):
  //   1.  Update("ab"),  Update("cd"), Update("ef")
  //   2.  Update("abc"), Update("def")
  virtual absl::Status Update(absl::string_view data) = 0;

  // Finalizes the hash computation and returns the resulting hash value. The
  // hash output is prepended with `0xff | key_id` (5 bytes).
  // After this method has been called, this object can no longer be used.
  // Requires exclusive access.
  virtual absl::StatusOr<std::string> GetPrehash() = 0;

  virtual ~ChunkedPrehashComputation() = default;
};

// Interface for chunked prehashes.
class ChunkedPrehash {
 public:
  // Creates an instance of a single chunked prehash computation.  Note that a
  // `ChunkedPrehash` object does not need to outlive the
  // `ChunkedPrehashComputation` objects that it creates.
  virtual absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
  CreateComputation() const = 0;

  virtual ~ChunkedPrehash() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_CHUNKED_PREHASH_H_
