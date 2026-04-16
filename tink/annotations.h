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
////////////////////////////////////////////////////////////////////////////////
#ifndef TINK_ANNOTATIONS_ANNOTATIONS_H_
#define TINK_ANNOTATIONS_ANNOTATIONS_H_

#include "absl/base/nullability.h"

ABSL_POINTERS_DEFAULT_NONNULL

namespace crypto {
namespace tink {

// Represents custom annotations that can be attached to a `KeysetHandle`.
//
// Subclassing this class allows users to attach any needed custom information
// to a `KeysetHandle` via `KeysetHandleBuilder::AddAnnotations<T>()`.
//
// `KeysetHandleBuilder::AddAnnotations` deprecates `monitoring_annotations` and
// `monitoring_annotations` in `KeysetHandle` constructor and method arguments.
class Annotations {
 public:
  Annotations() = default;
  Annotations(const Annotations&) = default;
  Annotations(Annotations&&) = default;
  Annotations& operator=(const Annotations&) = default;
  Annotations& operator=(Annotations&&) = default;
  virtual ~Annotations() = default;

  // Returns a deep copy of this object.
  virtual Annotations* Clone() const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_ANNOTATIONS_ANNOTATIONS_H_
