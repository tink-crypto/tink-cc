// Copyright 2025 Google LLC
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
#ifndef TINK_INTERNAL_MONITORING_CONTEXT_H_
#define TINK_INTERNAL_MONITORING_CONTEXT_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/internal/monitoring_key_set_info.h"

namespace crypto::tink::internal {

// Defines a context for monitoring events, wich includes the primitive and API
// used, and info on the keyset.
class MonitoringContext {
 public:
  // Construct a new context for the given `primitive`, `api_function` and
  // `keyset_info`.
  MonitoringContext(absl::string_view primitive, absl::string_view api_function,
                    const MonitoringKeySetInfo& keyset_info)
      : primitive_(primitive),
        api_function_(api_function),
        keyset_info_(keyset_info) {}

  // Returns the primitive.
  std::string GetPrimitive() const { return primitive_; }
  // Returns the API function.
  std::string GetApi() const { return api_function_; }
  // Returns a constant reference to the keyset info.
  const MonitoringKeySetInfo& GetKeySetInfo() const { return keyset_info_; }

 private:
  const std::string primitive_;
  const std::string api_function_;
  const MonitoringKeySetInfo keyset_info_;
};

}  // namespace crypto::tink::internal

#endif  // TINK_INTERNAL_MONITORING_CONTEXT_H_
