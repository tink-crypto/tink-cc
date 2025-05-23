// Copyright 2017 Google LLC
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
// This code was unceremoniously lifted from the version at
// github.com/google/lmctfy with a few minor modifications mainly to reduce the
// dependencies.

#ifndef TINK_UTIL_STATUS_H_
#define TINK_UTIL_STATUS_H_

#include "absl/status/status.h"

#define TINK_USE_ABSL_STATUS

namespace crypto {
namespace tink {
namespace util {

// A legacy alias for absl::Status. Status can be inlined to make user code
// cleaner. We currently do not plan to remove it.
using Status = absl::Status;

// A legacy alias for absl::OkStatus(). Returns an OK status, equivalent to a
// default constructed instance. OkStatus can be inlined to make user code
// cleaner. We currently do not plan to remove OkStatus.
inline absl::Status OkStatus() { return absl::OkStatus(); }

}  // namespace util
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_STATUS_H_
