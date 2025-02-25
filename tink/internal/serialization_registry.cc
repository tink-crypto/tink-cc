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

#include "tink/internal/serialization_registry.h"

#include <memory>
#include <typeinfo>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/types/optional.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/parser_index.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serializer_index.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

SerializationRegistry::Builder::Builder(const SerializationRegistry& registry)
    : Builder(registry.parameters_parsers_, registry.parameters_serializers_,
              registry.key_parsers_, registry.key_serializers_) {}

absl::Status SerializationRegistry::Builder::RegisterParametersParser(
    ParametersParser* parser) {
  ParserIndex index = parser->Index();
  auto it = parameters_parsers_.find(index);
  if (it != parameters_parsers_.end()) {
    if (parameters_parsers_[index] != parser) {
      return absl::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing parameters parser.");
    }
  }
  parameters_parsers_.insert({parser->Index(), parser});
  return absl::OkStatus();
}

absl::Status SerializationRegistry::Builder::RegisterParametersSerializer(
    ParametersSerializer* serializer) {
  SerializerIndex index = serializer->Index();
  auto it = parameters_serializers_.find(index);
  if (it != parameters_serializers_.end()) {
    if (parameters_serializers_[index] != serializer) {
      return absl::Status(
          absl::StatusCode::kAlreadyExists,
          "Attempted to update existing parameters serializer.");
    }
  }
  parameters_serializers_.insert({serializer->Index(), serializer});
  return absl::OkStatus();
}

absl::Status SerializationRegistry::Builder::RegisterKeyParser(
    KeyParser* parser) {
  ParserIndex index = parser->Index();
  auto it = key_parsers_.find(index);
  if (it != key_parsers_.end()) {
    if (key_parsers_[index] != parser) {
      return absl::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing key parser.");
    }
  }
  key_parsers_.insert({parser->Index(), parser});
  return absl::OkStatus();
}

absl::Status SerializationRegistry::Builder::RegisterKeySerializer(
    KeySerializer* serializer) {
  SerializerIndex index = serializer->Index();
  auto it = key_serializers_.find(index);
  if (it != key_serializers_.end()) {
    if (key_serializers_[index] != serializer) {
      return absl::Status(absl::StatusCode::kAlreadyExists,
                          "Attempted to update existing key serializer.");
    }
  }
  key_serializers_.insert({serializer->Index(), serializer});
  return absl::OkStatus();
}

SerializationRegistry SerializationRegistry::Builder::Build() && {
  return SerializationRegistry(
      std::move(parameters_parsers_), std::move(parameters_serializers_),
      std::move(key_parsers_), std::move(key_serializers_));
}

absl::StatusOr<std::unique_ptr<Parameters>>
SerializationRegistry::ParseParameters(
    const Serialization& serialization) const {
  ParserIndex index = ParserIndex::Create(serialization);
  auto it = parameters_parsers_.find(index);
  if (it == parameters_parsers_.end()) {
    return absl::Status(
        absl::StatusCode::kNotFound,
        absl::StrFormat("No parameters parser found for parameters type %s",
                        typeid(serialization).name()));
  }

  return parameters_parsers_.at(index)->ParseParameters(serialization);
}

absl::StatusOr<std::unique_ptr<Parameters>>
SerializationRegistry::ParseParametersWithLegacyFallback(
    const Serialization& serialization) const {
  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      ParseParameters(serialization);
  if (parameters.status().code() == absl::StatusCode::kNotFound) {
    const ProtoParametersSerialization* proto_serialization =
        dynamic_cast<const ProtoParametersSerialization*>(&serialization);
    if (proto_serialization == nullptr) {
      return absl::Status(
          absl::StatusCode::kInternal,
          "Failed to convert serialization to ProtoParametersSerialization.");
    }
    return {absl::make_unique<LegacyProtoParameters>(*proto_serialization)};
  }
  if (!parameters.ok()) {
    return parameters.status();
  }
  return parameters;
}

absl::StatusOr<std::unique_ptr<Key>> SerializationRegistry::ParseKey(
    const Serialization& serialization,
    absl::optional<SecretKeyAccessToken> token) const {
  ParserIndex index = ParserIndex::Create(serialization);
  auto it = key_parsers_.find(index);
  if (it == key_parsers_.end()) {
    return absl::Status(
        absl::StatusCode::kNotFound,
        absl::StrFormat("No key parser found for serialization type %s",
                        typeid(serialization).name()));
  }

  return key_parsers_.at(index)->ParseKey(serialization, token);
}

absl::StatusOr<std::unique_ptr<Key>>
SerializationRegistry::ParseKeyWithLegacyFallback(
    const Serialization& serialization, SecretKeyAccessToken token) const {
  absl::StatusOr<std::unique_ptr<Key>> key = ParseKey(serialization, token);
  if (key.status().code() == absl::StatusCode::kNotFound) {
    const ProtoKeySerialization* proto_serialization =
        dynamic_cast<const ProtoKeySerialization*>(&serialization);
    if (proto_serialization == nullptr) {
      return absl::Status(
          absl::StatusCode::kInternal,
          "Failed to convert serialization to ProtoKeySerialization.");
    }
    absl::StatusOr<LegacyProtoKey> proto_key =
        internal::LegacyProtoKey::Create(*proto_serialization, token);
    if (!proto_key.ok()) {
      return proto_key.status();
    }
    return {absl::make_unique<LegacyProtoKey>(std::move(*proto_key))};
  }
  if (!key.ok()) {
    return key.status();
  }
  return key;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
