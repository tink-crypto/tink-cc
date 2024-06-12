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

#ifndef TINK_INTERNAL_DFSAN_FORWARDERS_H_
#define TINK_INTERNAL_DFSAN_FORWARDERS_H_

#include <cstddef>

#include "absl/base/config.h"

#if ABSL_HAVE_FEATURE(dataflow_sanitizer)
#error Tink does not support DFSan in Open Source -- please file an issue with your use case
#endif

namespace crypto {
namespace tink {
namespace internal {

#if ABSL_HAVE_FEATURE(dataflow_sanitizer)

template <typename T>
void CutAllFlows(T& t) {
  dfsan_set_label(dfsan_label{0}, &t, sizeof(t));
}

inline void DfsanClearLabel(const void* ptr, size_t size) {
  dfsan_set_label(dfsan_label{0}, const_cast<void*>(ptr), size);
}

using dfsan::ScopedAssumeRegionCoreDumpSafe;

#else

template <typename T>
inline void CutAllFlows(T& t) {}

inline void DfsanClearLabel(const void* ptr, size_t size) {}

class ScopedAssumeRegionCoreDumpSafe {
 public:
  ScopedAssumeRegionCoreDumpSafe(const void* ptr, size_t size) {}
  ~ScopedAssumeRegionCoreDumpSafe() = default;
};

#endif

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_DFSAN_FORWARDERS_H_
