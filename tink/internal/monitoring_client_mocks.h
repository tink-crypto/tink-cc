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
#ifndef TINK_INTERNAL_MONITORING_CLIENT_MOCKS_H_
#define TINK_INTERNAL_MONITORING_CLIENT_MOCKS_H_

#include <cstdint>
#include <memory>

#include "gmock/gmock.h"
#include "tink/internal/monitoring.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Mock MonitoringClientFactory class.
class MockMonitoringClientFactory : public MonitoringClientFactory {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<MonitoringClient>>, New,
              (const MonitoringContext& context), (override));
};

// Mock MonitoringClient class.
class MockMonitoringClient : public MonitoringClient {
 public:
  MOCK_METHOD(void, Log, (uint32_t key_id, int64_t num_bytes_as_input),
              (override));
  MOCK_METHOD(void, LogFailure, (), (override));
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MONITORING_CLIENT_MOCKS_H_
