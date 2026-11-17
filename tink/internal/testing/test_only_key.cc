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
///////////////////////////////////////////////////////////////////////////////

#include "tink/internal/testing/test_only_key.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/output_prefix_util.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::TestOnlyKeyFormat;
using ::google::crypto::tink::internal::KeyDataTP;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;
using TestOnlyKeyProto = ::google::crypto::tink::TestOnlyKey;
using Variant = TestOnlyParameters::Variant;

absl::StatusOr<Variant> ToVariant(OutputPrefixTypeTP output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeTP::kTink:
      return Variant::kTink;
    case OutputPrefixTypeTP::kCrunchy:
      return Variant::kCrunchy;
    case OutputPrefixTypeTP::kLegacy:
      return Variant::kLegacy;
    case OutputPrefixTypeTP::kRaw:
      return Variant::kNoPrefix;
    default:
      return absl::InvalidArgumentError("Invalid output prefix type");
  }
}

absl::StatusOr<OutputPrefixTypeTP> ToOutputPrefixType(Variant variant) {
  switch (variant) {
    case Variant::kTink:
      return OutputPrefixTypeTP::kTink;
    case Variant::kCrunchy:
      return OutputPrefixTypeTP::kCrunchy;
    case Variant::kLegacy:
      return OutputPrefixTypeTP::kLegacy;
    case Variant::kNoPrefix:
      return OutputPrefixTypeTP::kRaw;
    default:
      return absl::InvalidArgumentError("Invalid variant");
  }
}

absl::StatusOr<std::string> ComputeTestOnlyOutputPrefix(
    const TestOnlyParameters& parameters, absl::optional<int> id_requirement) {
  if (parameters.HasIdRequirement() != id_requirement.has_value()) {
    return absl::InvalidArgumentError(
        "The ID requirement doesn't match the parameters");
  }
  switch (parameters.GetVariant()) {
    case Variant::kNoPrefix:
      return std::string("");
    case Variant::kCrunchy:
    case Variant::kLegacy:
      return internal::ComputeOutputPrefix(0, *id_requirement);
    case Variant::kTink:
      return internal::ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::InvalidArgumentError("Invalid variant");
  }
}

absl::StatusOr<TestOnlyParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTestOnlyKeyTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL");
  }
  TestOnlyKeyFormat key_format;
  if (!key_format.ParseFromString(serialization.GetKeyTemplate().value())) {
    return absl::InvalidArgumentError("Failed to parse the key format");
  }
  if (key_format.key_size() != kTestOnlyKeySizeInBytes) {
    return absl::InvalidArgumentError("Invalid key format");
  }
  ABSL_ASSIGN_OR_RETURN(
      Variant variant,
      ToVariant(serialization.GetKeyTemplate().output_prefix_type()));
  return TestOnlyParameters::Create(variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const TestOnlyParameters& parameters) {
  ABSL_ASSIGN_OR_RETURN(OutputPrefixTypeTP output_prefix_type,
                        ToOutputPrefixType(parameters.GetVariant()));
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);
  return ProtoParametersSerialization::Create(
      kTestOnlyKeyTypeUrl, output_prefix_type, key_format.SerializeAsString());
}

absl::StatusOr<TestOnlyAsymmetricParameters> ParseAsymmetricParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTestOnlyPrivateKeyTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL");
  }
  TestOnlyKeyFormat key_format;
  if (!key_format.ParseFromString(serialization.GetKeyTemplate().value())) {
    return absl::InvalidArgumentError("Failed to parse the key format");
  }
  if (key_format.key_size() != kTestOnlyKeySizeInBytes) {
    return absl::InvalidArgumentError("Invalid key format");
  }
  ABSL_ASSIGN_OR_RETURN(
      Variant variant,
      ToVariant(serialization.GetKeyTemplate().output_prefix_type()));
  return TestOnlyAsymmetricParameters::Create(variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeAsymmetricParameters(
    const TestOnlyAsymmetricParameters& parameters) {
  ABSL_ASSIGN_OR_RETURN(OutputPrefixTypeTP output_prefix_type,
                        ToOutputPrefixType(parameters.GetVariant()));
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);
  return ProtoParametersSerialization::Create(kTestOnlyPrivateKeyTypeUrl,
                                              output_prefix_type,
                                              key_format.SerializeAsString());
}

absl::StatusOr<TestOnlyParameters> GetParameters(
    const ProtoKeySerialization& serialization) {
  ABSL_ASSIGN_OR_RETURN(Variant variant,
                        ToVariant(serialization.GetOutputPrefixTypeTP()));
  return TestOnlyParameters::Create(variant);
}

absl::StatusOr<ProtoKeySerialization> CreateKeySerialization(
    absl::string_view type_url, absl::string_view serialized_key,
    SecretKeyAccessToken token, KeyDataTP::KeyMaterialTypeTP key_material_type,
    const Key& key) {
  const auto& parameters =
      static_cast<const TestOnlyParameters&>(key.GetParameters());
  ABSL_ASSIGN_OR_RETURN(OutputPrefixTypeTP output_prefix_type,
                        ToOutputPrefixType(parameters.GetVariant()));
  return ProtoKeySerialization::Create(
      type_url, RestrictedData(serialized_key, token), key_material_type,
      output_prefix_type, key.GetIdRequirement());
}

absl::StatusOr<TestOnlySymmetricKey> ParseKey(
    const ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kTestOnlyKeyTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  TestOnlyKeyProto key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse the key");
  }
  if (key.version() != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted");
  }
  ABSL_ASSIGN_OR_RETURN(TestOnlyParameters parameters,
                        GetParameters(serialization));
  return TestOnlySymmetricKey::Create(
      parameters, RestrictedData(key.key_value(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const TestOnlySymmetricKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  TestOnlyKeyProto proto_key;
  proto_key.set_version(0);
  proto_key.set_key_value(
      key.GetKeyBytes(GetPartialKeyAccess()).GetSecret(*token));
  return CreateKeySerialization(kTestOnlyKeyTypeUrl,
                                proto_key.SerializeAsString(), *token,
                                KeyDataTP::KeyMaterialTypeTP::kSymmetric, key);
}

using TestOnlyParametersParser =
    ParametersParserImpl<ProtoParametersSerialization, TestOnlyParameters>;
using TestOnlyParametersSerializer =
    ParametersSerializerImpl<TestOnlyParameters, ProtoParametersSerialization>;
using TestOnlySymmetricKeyParser =
    KeyParserImpl<ProtoKeySerialization, TestOnlySymmetricKey>;
using TestOnlySymmetricKeySerializer =
    KeySerializerImpl<TestOnlySymmetricKey, ProtoKeySerialization>;
using TestOnlyAsymmetricParametersParser =
    ParametersParserImpl<ProtoParametersSerialization,
                         TestOnlyAsymmetricParameters>;
using TestOnlyAsymmetricParametersSerializer =
    ParametersSerializerImpl<TestOnlyAsymmetricParameters,
                             ProtoParametersSerialization>;

TestOnlyParametersParser* GetParametersParser() {
  static auto* parser =
      new TestOnlyParametersParser(kTestOnlyKeyTypeUrl, ParseParameters);
  return parser;
}

TestOnlyParametersSerializer* GetParametersSerializer() {
  static auto* serializer = new TestOnlyParametersSerializer(
      kTestOnlyKeyTypeUrl, SerializeParameters);
  return serializer;
}

TestOnlySymmetricKeyParser* GetKeyParser() {
  static auto* parser =
      new TestOnlySymmetricKeyParser(kTestOnlyKeyTypeUrl, ParseKey);
  return parser;
}

TestOnlySymmetricKeySerializer* GetKeySerializer() {
  static auto* serializer = new TestOnlySymmetricKeySerializer(SerializeKey);
  return serializer;
}

TestOnlyAsymmetricParametersParser* GetAsymmetricParametersParser() {
  static auto* parser = new TestOnlyAsymmetricParametersParser(
      kTestOnlyPrivateKeyTypeUrl, ParseAsymmetricParameters);
  return parser;
}

TestOnlyAsymmetricParametersSerializer* GetAsymmetricParametersSerializer() {
  static auto* serializer = new TestOnlyAsymmetricParametersSerializer(
      kTestOnlyPrivateKeyTypeUrl, SerializeAsymmetricParameters);
  return serializer;
}

}  // namespace

absl::StatusOr<TestOnlyParameters> TestOnlyParameters::Create(Variant variant) {
  switch (variant) {
    case Variant::kTink:
    case Variant::kCrunchy:
    case Variant::kLegacy:
    case Variant::kNoPrefix:
      return TestOnlyParameters(variant);
    default:
      return absl::InvalidArgumentError("Invalid variant");
  }
}

bool TestOnlyParameters::operator==(const Parameters& other) const {
  const TestOnlyParameters* that =
      dynamic_cast<const TestOnlyParameters*>(&other);
  return that != nullptr && variant_ == that->variant_;
}

absl::StatusOr<TestOnlySymmetricKey> TestOnlySymmetricKey::Create(
    const TestOnlyParameters& parameters, const RestrictedData& key_bytes,
    absl::optional<int> id_requirement, PartialKeyAccessToken token) {
  ABSL_ASSIGN_OR_RETURN(
      std::string output_prefix,
      ComputeTestOnlyOutputPrefix(parameters, id_requirement));
  return TestOnlySymmetricKey(parameters, key_bytes, id_requirement,
                              std::move(output_prefix));
}

bool TestOnlySymmetricKey::operator==(const Key& other) const {
  const TestOnlySymmetricKey* that =
      dynamic_cast<const TestOnlySymmetricKey*>(&other);
  return that != nullptr && parameters_ == that->parameters_ &&
         key_bytes_ == that->key_bytes_ &&
         id_requirement_ == that->id_requirement_;
}

absl::Status RegisterTestOnlyProtoSerialization() {
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();
  absl::Status status =
      registry.RegisterParametersParser(GetParametersParser());
  if (!status.ok()) {
    return status;
  }
  status = registry.RegisterParametersSerializer(GetParametersSerializer());
  if (!status.ok()) {
    return status;
  }
  status = registry.RegisterKeyParser(GetKeyParser());
  if (!status.ok()) {
    return status;
  }
  status = registry.RegisterKeySerializer(GetKeySerializer());
  if (!status.ok()) {
    return status;
  }
  status = registry.RegisterParametersParser(GetAsymmetricParametersParser());
  if (!status.ok()) {
    return status;
  }
  return registry.RegisterParametersSerializer(
      GetAsymmetricParametersSerializer());
}

absl::StatusOr<std::unique_ptr<Key>> CreateTestOnlyKey(
    const TestOnlyParameters& parameters, absl::optional<int> id_requirement) {
  RestrictedData key_bytes(kTestOnlyKeySizeInBytes);
  ABSL_ASSIGN_OR_RETURN(
      TestOnlySymmetricKey key,
      TestOnlySymmetricKey::Create(parameters, key_bytes, id_requirement,
                                   GetPartialKeyAccess()));
  return {std::make_unique<TestOnlySymmetricKey>(std::move(key))};
}

absl::StatusOr<std::unique_ptr<Aead>> NewTestOnlyAead(
    const TestOnlySymmetricKey& key) {
  return {std::make_unique<test::DummyAead>(absl::BytesToHexString(
      key.GetKeyBytes(GetPartialKeyAccess())
          .GetSecret(GetInsecureSecretKeyAccessInternal())))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
