// Copyright 2023 Google LLC
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

#include "tink/internal/mutable_serialization_registry.h"

#include <memory>
#include <utility>

#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

MutableSerializationRegistry& MutableSerializationRegistry::GlobalInstance() {
  static MutableSerializationRegistry* instance =
      new MutableSerializationRegistry();
  return *instance;
}

absl::Status MutableSerializationRegistry::RegisterParametersParser(
    ParametersParser* parser) {
  absl::WriterMutexLock lock(&registry_mutex_);
  SerializationRegistry::Builder builder(registry_);
  absl::Status status = builder.RegisterParametersParser(parser);
  if (!status.ok()) return status;
  registry_ = std::move(builder).Build();
  return absl::OkStatus();
}

absl::Status MutableSerializationRegistry::RegisterParametersSerializer(
    ParametersSerializer* serializer) {
  absl::WriterMutexLock lock(&registry_mutex_);
  SerializationRegistry::Builder builder(registry_);
  absl::Status status = builder.RegisterParametersSerializer(serializer);
  if (!status.ok()) return status;
  registry_ = std::move(builder).Build();
  return absl::OkStatus();
}

absl::Status MutableSerializationRegistry::RegisterKeyParser(
    KeyParser* parser) {
  absl::WriterMutexLock lock(&registry_mutex_);
  SerializationRegistry::Builder builder(registry_);
  absl::Status status = builder.RegisterKeyParser(parser);
  if (!status.ok()) return status;
  registry_ = std::move(builder).Build();
  return absl::OkStatus();
}

absl::Status MutableSerializationRegistry::RegisterKeySerializer(
    KeySerializer* serializer) {
  absl::WriterMutexLock lock(&registry_mutex_);
  SerializationRegistry::Builder builder(registry_);
  absl::Status status = builder.RegisterKeySerializer(serializer);
  if (!status.ok()) return status;
  registry_ = std::move(builder).Build();
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<Parameters>>
MutableSerializationRegistry::ParseParameters(
    const Serialization& serialization) {
  absl::ReaderMutexLock lock(&registry_mutex_);
  return registry_.ParseParameters(serialization);
}

absl::StatusOr<std::unique_ptr<Parameters>>
MutableSerializationRegistry::ParseParametersWithLegacyFallback(
    const Serialization& serialization) {
  absl::ReaderMutexLock lock(&registry_mutex_);
  return registry_.ParseParametersWithLegacyFallback(serialization);
}

absl::StatusOr<std::unique_ptr<Key>> MutableSerializationRegistry::ParseKey(
    const Serialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  absl::ReaderMutexLock lock(&registry_mutex_);
  return registry_.ParseKey(serialization, token);
}

absl::StatusOr<std::unique_ptr<Key>>
MutableSerializationRegistry::ParseKeyWithLegacyFallback(
    const Serialization& serialization, SecretKeyAccessToken token) {
  absl::ReaderMutexLock lock(&registry_mutex_);
  return registry_.ParseKeyWithLegacyFallback(serialization, token);
}

void MutableSerializationRegistry::Reset() {
  absl::WriterMutexLock lock(&registry_mutex_);
  registry_ = SerializationRegistry();
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
