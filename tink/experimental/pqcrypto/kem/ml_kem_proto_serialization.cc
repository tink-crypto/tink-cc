// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/kem/ml_kem_proto_serialization.h"

#include <cstdint>
#include <string>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_parameters.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_private_key.h"
#include "tink/experimental/pqcrypto/kem/ml_kem_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/proto_parser.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace {

bool MlKemKeySizeEnumIsValid(int c) { return c >= 0 && c <= 1; }

enum class MlKemKeySizeEnum : uint32_t {
  kUnknown = 0,
  kMlKem768 = 1,
};

struct MlKemParamsStruct {
  MlKemKeySizeEnum ml_kem_key_size;

  inline static internal::ProtoParser<MlKemParamsStruct> CreateParser() {
    return internal::ProtoParserBuilder<MlKemParamsStruct>()
        .AddEnumField(1, &MlKemParamsStruct::ml_kem_key_size,
                      &MlKemKeySizeEnumIsValid)
        .BuildOrDie();
  }
};

struct MlKemKeyFormatStruct {
  uint32_t version;
  MlKemParamsStruct params;

  inline static internal::ProtoParser<MlKemKeyFormatStruct>& GetParser() {
    static absl::NoDestructor<internal::ProtoParser<MlKemKeyFormatStruct>>
        parser{internal::ProtoParserBuilder<MlKemKeyFormatStruct>()
                   .AddUint32Field(1, &MlKemKeyFormatStruct::version)
                   .AddMessageField(2, &MlKemKeyFormatStruct::params,
                                    MlKemParamsStruct::CreateParser())
                   .BuildOrDie()};
    return *parser;
  }
};

struct MlKemPublicKeyStruct {
  uint32_t version = 0;
  std::string key_value = {};
  MlKemParamsStruct params = {};

  inline static internal::ProtoParser<MlKemPublicKeyStruct> CreateParser() {
    return internal::ProtoParserBuilder<MlKemPublicKeyStruct>()
        .AddUint32Field(1, &MlKemPublicKeyStruct::version)
        .AddBytesStringField(2, &MlKemPublicKeyStruct::key_value)
        .AddMessageField(3, &MlKemPublicKeyStruct::params,
                         MlKemParamsStruct::CreateParser())
        .BuildOrDie();
  }

  inline static internal::ProtoParser<MlKemPublicKeyStruct>& GetParser() {
    static absl::NoDestructor<internal::ProtoParser<MlKemPublicKeyStruct>>
        parser{CreateParser()};
    return *parser;
  }
};

struct MlKemPrivateKeyStruct {
  uint32_t version = 0;
  SecretData key_value = {};
  MlKemPublicKeyStruct public_key = {};

  inline static internal::ProtoParser<MlKemPrivateKeyStruct>& GetParser() {
    static absl::NoDestructor<internal::ProtoParser<MlKemPrivateKeyStruct>>
        parser{
            internal::ProtoParserBuilder<MlKemPrivateKeyStruct>()
                .AddUint32Field(1, &MlKemPrivateKeyStruct::version)
                .AddBytesSecretDataField(2, &MlKemPrivateKeyStruct::key_value)
                .AddMessageField(3, &MlKemPrivateKeyStruct::public_key,
                                 MlKemPublicKeyStruct::CreateParser())
                .BuildOrDie()};
    return *parser;
  }
};

using MlKemProtoParametersParserImpl =
    internal::ParametersParserImpl<internal::ProtoParametersSerialization,
                                   MlKemParameters>;
using MlKemProtoParametersSerializerImpl =
    internal::ParametersSerializerImpl<MlKemParameters,
                                       internal::ProtoParametersSerialization>;
using MlKemProtoPublicKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPublicKey>;
using MlKemProtoPublicKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPublicKey,
                                internal::ProtoKeySerialization>;
using MlKemProtoPrivateKeyParserImpl =
    internal::KeyParserImpl<internal::ProtoKeySerialization, MlKemPrivateKey>;
using MlKemProtoPrivateKeySerializerImpl =
    internal::KeySerializerImpl<MlKemPrivateKey,
                                internal::ProtoKeySerialization>;

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.MlKemPublicKey";

absl::StatusOr<MlKemParameters::Variant> ToVariant(
    internal::OutputPrefixTypeEnum output_prefix_type) {
  switch (output_prefix_type) {
    case internal::OutputPrefixTypeEnum::kTink:
      return MlKemParameters::Variant::kTink;
    case internal::OutputPrefixTypeEnum::kRaw:
      return absl::InvalidArgumentError(
          "Invalid output prefix type RAW for MlKemParameters");
    default:
      return absl::InvalidArgumentError(
          "Could not determine MlKemParameters::Variant");
  }
}

absl::StatusOr<internal::OutputPrefixTypeEnum> ToOutputPrefixType(
    MlKemParameters::Variant variant) {
  switch (variant) {
    case MlKemParameters::Variant::kTink:
      return internal::OutputPrefixTypeEnum::kTink;
    default:
      return absl::InvalidArgumentError(
          "Could not determine output prefix type");
  }
}

absl::StatusOr<int> ToKeySize(MlKemKeySizeEnum key_size) {
  switch (key_size) {
    case MlKemKeySizeEnum::kMlKem768:
      return 768;
    default:
      return absl::InvalidArgumentError(
          "Could not determine MlKemParameters' key size");
  }
}

absl::StatusOr<MlKemKeySizeEnum> ToProtoKeySize(int key_size) {
  switch (key_size) {
    case 768:
      return MlKemKeySizeEnum::kMlKem768;
    default:
      return absl::InvalidArgumentError("Could not determine MlKemKeySize");
  }
}

absl::StatusOr<MlKemParameters> ToParameters(
    internal::OutputPrefixTypeEnum output_prefix_type,
    const MlKemParamsStruct& params) {
  absl::StatusOr<MlKemParameters::Variant> variant =
      ToVariant(output_prefix_type);
  if (!variant.ok()) {
    return variant.status();
  }

  absl::StatusOr<int> key_size = ToKeySize(params.ml_kem_key_size);
  if (!key_size.ok()) {
    return key_size.status();
  }

  return MlKemParameters::Create(*key_size, *variant);
}

absl::StatusOr<MlKemParamsStruct> FromParameters(
    const MlKemParameters& parameters) {
  absl::StatusOr<MlKemKeySizeEnum> key_size =
      ToProtoKeySize(parameters.GetKeySize());
  if (!key_size.ok()) {
    return key_size.status();
  }

  MlKemParamsStruct params;
  params.ml_kem_key_size = *key_size;
  return params;
}

absl::StatusOr<MlKemParameters> ParseParameters(
    const internal::ProtoParametersSerialization& serialization) {
  const internal::KeyTemplateStruct key_template =
      serialization.GetKeyTemplateStruct();

  if (key_template.type_url != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemParameters.");
  }

  absl::StatusOr<MlKemKeyFormatStruct> proto_key_format =
      MlKemKeyFormatStruct::GetParser().Parse(key_template.value);
  if (!proto_key_format.ok()) {
    return proto_key_format.status();
  }
  if (proto_key_format->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }
  return ToParameters(key_template.output_prefix_type,
                      proto_key_format->params);
}

absl::StatusOr<MlKemPublicKey> ParsePublicKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> /*token*/) {
  if (serialization.TypeUrl() != kPublicTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemPublicKey.");
  }

  absl::StatusOr<MlKemPublicKeyStruct> proto_key =
      MlKemPublicKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(
              InsecureSecretKeyAccess::Get()));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlKemParameters> parameters =
      ToParameters(serialization.GetOutputPrefixTypeEnum(), proto_key->params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  return MlKemPublicKey::Create(*parameters, proto_key->key_value,
                                serialization.IdRequirement(),
                                GetPartialKeyAccess());
}

absl::StatusOr<MlKemPrivateKey> ParsePrivateKey(
    const internal::ProtoKeySerialization& serialization,
    absl::optional<SecretKeyAccessToken> token) {
  if (serialization.TypeUrl() != kPrivateTypeUrl) {
    return absl::InvalidArgumentError(
        "Wrong type URL when parsing MlKemPrivateKey.");
  }
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }

  absl::StatusOr<MlKemPrivateKeyStruct> proto_key =
      MlKemPrivateKeyStruct::GetParser().Parse(
          serialization.SerializedKeyProto().GetSecret(*token));
  if (!proto_key.ok()) {
    return proto_key.status();
  }
  if (proto_key->version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted.");
  }

  absl::StatusOr<MlKemParameters> parameters = ToParameters(
      serialization.GetOutputPrefixTypeEnum(), proto_key->public_key.params);
  if (!parameters.ok()) {
    return parameters.status();
  }

  absl::StatusOr<MlKemPublicKey> public_key = MlKemPublicKey::Create(
      *parameters, proto_key->public_key.key_value,
      serialization.IdRequirement(), GetPartialKeyAccess());
  if (!public_key.ok()) {
    return public_key.status();
  }

  return MlKemPrivateKey::Create(*public_key,
                                 RestrictedData(proto_key->key_value, *token),
                                 GetPartialKeyAccess());
}

absl::StatusOr<internal::ProtoParametersSerialization> SerializeParameters(
    const MlKemParameters& parameters) {
  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(parameters.GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  absl::StatusOr<MlKemParamsStruct> params = FromParameters(parameters);
  if (!params.ok()) {
    return params.status();
  }
  MlKemKeyFormatStruct proto_key_format;
  proto_key_format.params = *params;
  proto_key_format.version = 0;

  absl::StatusOr<std::string> serialized =
      MlKemKeyFormatStruct::GetParser().SerializeIntoString(proto_key_format);
  if (!serialized.ok()) {
    return serialized.status();
  }

  return internal::ProtoParametersSerialization::Create(
      kPrivateTypeUrl, *output_prefix_type, *serialized);
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePublicKey(
    const MlKemPublicKey& key, absl::optional<SecretKeyAccessToken> token) {
  absl::StatusOr<MlKemParamsStruct> params =
      FromParameters(key.GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlKemPublicKeyStruct proto_key;
  proto_key.version = 0;
  proto_key.params = *params;
  proto_key.key_value = key.GetPublicKeyBytes(GetPartialKeyAccess());

  absl::StatusOr<std::string> serialized =
      MlKemPublicKeyStruct::GetParser().SerializeIntoString(proto_key);
  if (!serialized.ok()) {
    return serialized.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output =
      RestrictedData(*serialized, InsecureSecretKeyAccess::Get());
  return internal::ProtoKeySerialization::Create(
      kPublicTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPublic, *output_prefix_type,
      key.GetIdRequirement());
}

absl::StatusOr<internal::ProtoKeySerialization> SerializePrivateSeed(
    const MlKemPrivateKey& key, absl::optional<SecretKeyAccessToken> token) {
  if (!token.has_value()) {
    return absl::PermissionDeniedError("SecretKeyAccess is required");
  }
  absl::StatusOr<RestrictedData> restricted_input =
      key.GetPrivateSeedBytes(GetPartialKeyAccess());
  if (!restricted_input.ok()) {
    return restricted_input.status();
  }

  absl::StatusOr<MlKemParamsStruct> params =
      FromParameters(key.GetPublicKey().GetParameters());
  if (!params.ok()) {
    return params.status();
  }

  MlKemPrivateKeyStruct proto_private_key;
  proto_private_key.version = 0;
  proto_private_key.public_key.version = 0;
  proto_private_key.public_key.params = *params;
  proto_private_key.public_key.key_value =
      key.GetPublicKey().GetPublicKeyBytes(GetPartialKeyAccess());
  proto_private_key.key_value = restricted_input->Get(*token);

  absl::StatusOr<SecretData> serialized =
      MlKemPrivateKeyStruct::GetParser().SerializeIntoSecretData(
          proto_private_key);
  if (!serialized.ok()) {
    return serialized.status();
  }

  absl::StatusOr<internal::OutputPrefixTypeEnum> output_prefix_type =
      ToOutputPrefixType(key.GetPublicKey().GetParameters().GetVariant());
  if (!output_prefix_type.ok()) {
    return output_prefix_type.status();
  }

  RestrictedData restricted_output = RestrictedData(*serialized, *token);
  return internal::ProtoKeySerialization::Create(
      kPrivateTypeUrl, restricted_output,
      internal::KeyMaterialTypeEnum::kAsymmetricPrivate, *output_prefix_type,
      key.GetIdRequirement());
}

MlKemProtoParametersParserImpl& MlKemProtoParametersParser() {
  static auto parser =
      new MlKemProtoParametersParserImpl(kPrivateTypeUrl, ParseParameters);
  return *parser;
}

MlKemProtoParametersSerializerImpl& MlKemProtoParametersSerializer() {
  static auto serializer = new MlKemProtoParametersSerializerImpl(
      kPrivateTypeUrl, SerializeParameters);
  return *serializer;
}

MlKemProtoPublicKeyParserImpl& MlKemProtoPublicKeyParser() {
  static auto* parser =
      new MlKemProtoPublicKeyParserImpl(kPublicTypeUrl, ParsePublicKey);
  return *parser;
}

MlKemProtoPublicKeySerializerImpl& MlKemProtoPublicKeySerializer() {
  static auto* serializer =
      new MlKemProtoPublicKeySerializerImpl(SerializePublicKey);
  return *serializer;
}

MlKemProtoPrivateKeyParserImpl& MlKemProtoPrivateKeyParser() {
  static auto* parser =
      new MlKemProtoPrivateKeyParserImpl(kPrivateTypeUrl, ParsePrivateKey);
  return *parser;
}

MlKemProtoPrivateKeySerializerImpl& MlKemProtoPrivateKeySerializer() {
  static auto* serializer =
      new MlKemProtoPrivateKeySerializerImpl(SerializePrivateSeed);
  return *serializer;
}

}  // namespace

absl::Status RegisterMlKemProtoSerialization() {
  absl::Status status =
      internal::MutableSerializationRegistry::GlobalInstance()
          .RegisterParametersParser(&MlKemProtoParametersParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterParametersSerializer(&MlKemProtoParametersSerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPublicKeyParser());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeySerializer(&MlKemProtoPublicKeySerializer());
  if (!status.ok()) {
    return status;
  }

  status = internal::MutableSerializationRegistry::GlobalInstance()
               .RegisterKeyParser(&MlKemProtoPrivateKeyParser());
  if (!status.ok()) {
    return status;
  }

  return internal::MutableSerializationRegistry::GlobalInstance()
      .RegisterKeySerializer(&MlKemProtoPrivateKeySerializer());
}

}  // namespace tink
}  // namespace crypto
