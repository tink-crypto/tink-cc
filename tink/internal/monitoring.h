// Copyright 2022 Google LLC
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
#ifndef TINK_INTERNAL_MONITORING_H_
#define TINK_INTERNAL_MONITORING_H_

#include <cstdint>
#include <memory>

#include "absl/status/statusor.h"
#include "tink/internal/monitoring_context.h"

namespace crypto {
namespace tink {
namespace internal {

// Interface for a monitoring client which can be registered with Tink. A
// monitoring client getis informed by Tink about certain events happening
// during cryptographic operations.
class MonitoringClient {
 public:
  virtual ~MonitoringClient() = default;
  // Logs a successful use of `key_id` on an input of `num_bytes_as_input`. Tink
  // primitive wrappers call this method when they successfully used a key to
  // carry out a primitive method, e.g. Aead::Encrypt(). As a consequence,
  // subclasses of MonitoringClient should be mindful on the amount of work
  // performed by this method, as this will be called on each cryptographic
  // operation. Implementations of MonitoringClient are responsible to add
  // context to identify, e.g., the primitive and the API function.
  virtual void Log(uint32_t key_id, int64_t num_bytes_as_input) = 0;

  // Logs a failure. Tink calls this method when a cryptographic operation
  // failed, e.g. no key could be found to decrypt a ciphertext. In this
  // case the failure is not associated with a specific key, therefore this
  // method has no arguments. The MonitoringClient implementation is responsible
  // to add context to identify where the failure comes from.
  virtual void LogFailure() = 0;
};

// Interface for a factory class that creates monitoring clients.
//
// Implementations of this interface should be thread-safe.
class MonitoringClientFactory {
 public:
  virtual ~MonitoringClientFactory() = default;
  // Create a new monitoring client that logs events related to the given
  // `context`.
  virtual absl::StatusOr<std::unique_ptr<internal::MonitoringClient>> New(
      const MonitoringContext& context) = 0;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MONITORING_H_
