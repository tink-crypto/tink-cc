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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/parameters.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::TestProto;
using ::google::crypto::tink::internal::OutputPrefixTypeTP;

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

using TestOnlyParametersParser =
    ParametersParserImpl<ProtoParametersSerialization, TestOnlyParameters>;
using TestOnlyParametersSerializer =
    ParametersSerializerImpl<TestOnlyParameters, ProtoParametersSerialization>;

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

absl::Status RegisterTestOnlyProtoSerialization() {
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();
  absl::Status status =
      registry.RegisterParametersParser(GetParametersParser());
  if (!status.ok()) {
    return status;
  }
  return registry.RegisterParametersSerializer(GetParametersSerializer());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
