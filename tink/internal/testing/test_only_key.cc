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
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/test_util.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::TestProto;
using ::google::crypto::tink::TestProtoWithoutCtype;
using ::google::crypto::tink::internal::KeyDataTP;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;

absl::StatusOr<std::string> ComputeTestOnlyOutputPrefix(
    TestOnlyParameters::Variant variant, absl::optional<int> id_requirement) {
  switch (variant) {
    case TestOnlyParameters::Variant::kNoPrefix:
      return std::string("");
    case TestOnlyParameters::Variant::kCrunchy:
    case TestOnlyParameters::Variant::kLegacy:
      if (!id_requirement.has_value()) {
        return absl::InvalidArgumentError("Missing ID requirement");
      }
      return ComputeOutputPrefix(0, *id_requirement);
    case TestOnlyParameters::Variant::kTink:
      if (!id_requirement.has_value()) {
        return absl::InvalidArgumentError("Missing ID requirement");
      }
      return ComputeOutputPrefix(1, *id_requirement);
    default:
      return absl::InvalidArgumentError("Invalid variant");
  }
}

absl::StatusOr<TestOnlyParameters::Variant> ToVariant(
    OutputPrefixTypeTP output_prefix_type) {
  switch (output_prefix_type) {
    case OutputPrefixTypeTP::kTink:
      return TestOnlyParameters::Variant::kTink;
    case OutputPrefixTypeTP::kCrunchy:
      return TestOnlyParameters::Variant::kCrunchy;
    case OutputPrefixTypeTP::kLegacy:
      return TestOnlyParameters::Variant::kLegacy;
    case OutputPrefixTypeTP::kRaw:
      return TestOnlyParameters::Variant::kNoPrefix;
    default:
      return absl::InvalidArgumentError("Invalid output prefix type");
  }
}

absl::StatusOr<OutputPrefixTypeTP> ToOutputPrefixType(
    TestOnlyParameters::Variant variant) {
  switch (variant) {
    case TestOnlyParameters::Variant::kTink:
      return OutputPrefixTypeTP::kTink;
    case TestOnlyParameters::Variant::kCrunchy:
      return OutputPrefixTypeTP::kCrunchy;
    case TestOnlyParameters::Variant::kLegacy:
      return OutputPrefixTypeTP::kLegacy;
    case TestOnlyParameters::Variant::kNoPrefix:
      return OutputPrefixTypeTP::kRaw;
    default:
      return absl::InvalidArgumentError("Invalid variant");
  }
}

absl::StatusOr<TestOnlyParameters> ParseParameters(
    const ProtoParametersSerialization& serialization) {
  if (serialization.GetKeyTemplate().type_url() != kTestOnlyKeyTypeUrl) {
    return absl::InvalidArgumentError("Wrong type URL");
  }
  TestProto key_format;
  if (!key_format.ParseFromString(serialization.GetKeyTemplate().value())) {
    return absl::InvalidArgumentError("Failed to parse the key format");
  }
  if (key_format.num() != kTestOnlyKeySizeInBytes ||
      !key_format.str().empty()) {
    return absl::InvalidArgumentError("Invalid key format");
  }
  absl::StatusOr<TestOnlyParameters::Variant> variant =
      ToVariant(serialization.GetKeyTemplate().output_prefix_type());
  if (!variant.ok()) {
    return variant.status();
  }
  return TestOnlyParameters::Create(*variant);
}

absl::StatusOr<ProtoParametersSerialization> SerializeParameters(
    const TestOnlyParameters& parameters) {
  absl::StatusOr<OutputPrefixTypeTP> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  TestProto key_format;
  key_format.set_num(kTestOnlyKeySizeInBytes);
  return ProtoParametersSerialization::Create(
      kTestOnlyKeyTypeUrl, *output_prefix_type, key_format.SerializeAsString());
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
  TestProtoWithoutCtype key;
  if (!key.ParseFromString(
          serialization.SerializedKeyProto().GetSecret(*token))) {
    return absl::InvalidArgumentError("Failed to parse the key");
  }
  absl::StatusOr<TestOnlyParameters::Variant> variant =
      ToVariant(serialization.GetOutputPrefixTypeTP());
  if (!variant.ok()) {
    return variant.status();
  }
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(*variant);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return TestOnlySymmetricKey::Create(
      *parameters, RestrictedData(key.str(), *token),
      serialization.IdRequirement(), GetPartialKeyAccess());
}

absl::StatusOr<ProtoKeySerialization> SerializeKey(
    const TestOnlySymmetricKey& key,
    absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  absl::StatusOr<OutputPrefixTypeTP> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }
  TestProtoWithoutCtype proto_key;
  proto_key.set_str(key.GetKeyBytes(GetPartialKeyAccess()).GetSecret(*token));
  std::string serialized_key = proto_key.SerializeAsString();
  return ProtoKeySerialization::Create(
      kTestOnlyKeyTypeUrl,
      RestrictedData(absl::string_view(serialized_key), *token),
      KeyDataTP::KeyMaterialTypeTP::kSymmetric, *output_prefix_type,
      key.GetIdRequirement());
}

using TestOnlyParametersParser =
    ParametersParserImpl<ProtoParametersSerialization, TestOnlyParameters>;
using TestOnlyParametersSerializer =
    ParametersSerializerImpl<TestOnlyParameters, ProtoParametersSerialization>;
using TestOnlySymmetricKeyParser =
    KeyParserImpl<ProtoKeySerialization, TestOnlySymmetricKey>;
using TestOnlySymmetricKeySerializer =
    KeySerializerImpl<TestOnlySymmetricKey, ProtoKeySerialization>;

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
  if (parameters.HasIdRequirement() != id_requirement.has_value()) {
    return absl::InvalidArgumentError(
        "The ID requirement doesn't match the parameters");
  }
  absl::StatusOr<std::string> output_prefix =
      ComputeTestOnlyOutputPrefix(parameters.GetVariant(), id_requirement);
  if (!output_prefix.ok()) {
    return output_prefix.status();
  }
  return TestOnlySymmetricKey(parameters, key_bytes, id_requirement,
                              *std::move(output_prefix));
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
  return registry.RegisterKeySerializer(GetKeySerializer());
}

absl::StatusOr<std::unique_ptr<Key>> CreateTestOnlyKey(
    const TestOnlyParameters& parameters, absl::optional<int> id_requirement) {
  absl::StatusOr<TestOnlySymmetricKey> key = TestOnlySymmetricKey::Create(
      parameters, RestrictedData(kTestOnlyKeySizeInBytes), id_requirement,
      GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return {std::make_unique<TestOnlySymmetricKey>(*std::move(key))};
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
