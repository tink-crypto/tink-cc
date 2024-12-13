// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_key_derivation_proto_serialization_impl.h"

#include <memory>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::google::crypto::tink::PrfBasedDeriverParams;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
constexpr absl::string_view kPrfKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
constexpr absl::string_view kDerivedKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
constexpr absl::string_view kPrfKeyValue = "0123456789abcdef";

KeyTemplate GetAesCmacPrfKeyTemplate() {
  AesCmacPrfKeyFormat key_format;
  key_format.set_version(0);
  key_format.set_key_size(kPrfKeyValue.size());
  KeyTemplate key_template;
  key_template.set_type_url(kPrfKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

AesCmacPrfParameters GetAesCmacPrfParameters() {
  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(kPrfKeyValue.size());
  CHECK_OK(parameters);
  return *parameters;
}

KeyTemplate GetXChaCha20Poly1305KeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(kDerivedKeyTypeUrl);
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  return key_template;
}

XChaCha20Poly1305Parameters GetXChaCha20Poly1305Parameters() {
  util::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  CHECK_OK(parameters);
  return *parameters;
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     RegisterTwiceSucceedsWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     RegisterTwiceSucceedsWithRegistryBuilder) {
  // TODO: b/378091229 - Consider disallowing duplicate registrations.
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
          builder),
      IsOk());
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
          builder),
      IsOk());
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, derived_key_template.output_prefix_type(),
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsTrue());

  const PrfBasedKeyDerivationParameters* prf_based_deriver_parameters =
      dynamic_cast<const PrfBasedKeyDerivationParameters*>(params->get());
  ASSERT_THAT(prf_based_deriver_parameters, NotNull());

  EXPECT_THAT(prf_based_deriver_parameters->GetPrfParameters(),
              Eq(GetAesCmacPrfParameters()));
  EXPECT_THAT(prf_based_deriver_parameters->GetDerivedKeyParameters(),
              Eq(GetXChaCha20Poly1305Parameters()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
          builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, derived_key_template.output_prefix_type(),
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsTrue());

  const PrfBasedKeyDerivationParameters* prf_based_deriver_parameters =
      dynamic_cast<const PrfBasedKeyDerivationParameters*>(params->get());
  ASSERT_THAT(prf_based_deriver_parameters, NotNull());

  EXPECT_THAT(prf_based_deriver_parameters->GetPrfParameters(),
              Eq(GetAesCmacPrfParameters()));
  EXPECT_THAT(prf_based_deriver_parameters->GetDerivedKeyParameters(),
              Eq(GetXChaCha20Poly1305Parameters()));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithInvalidSerialization) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Failed to parse PrfBasedKeyDerivationKeyFormat proto")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithMismatchedOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      GetXChaCha20Poly1305KeyTemplate();
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsed output prefix type must match derived "
                                 "key output prefix type")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithUnknownOutputPrefix) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();
  derived_key_template.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Could not determine XChaCha20Poly1305Parameters::Variant")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     ParseParametersWithInvalidPrfKeyTemplate) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() =
      GetXChaCha20Poly1305KeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      GetXChaCha20Poly1305KeyTemplate();
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::TINK,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(*serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr(
              "Non-PRF parameters stored in the `prf_key_template` field")));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeParametersWithMutableRegistry) {
  MutableSerializationRegistry registry;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithMutableRegistry(
          registry),
      IsOk());

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<internal::ProtoParametersSerialization>(
          *parameters);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(OutputPrefixType::TINK));

  PrfBasedDeriverKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.prf_key_template().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_format.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

TEST(PrfBasedKeyDerivationProtoSerializationTest,
     SerializeParametersWithRegistryBuilder) {
  SerializationRegistry::Builder builder;
  ASSERT_THAT(
      RegisterPrfBasedKeyDerivationProtoSerializationWithRegistryBuilder(
          builder),
      IsOk());
  SerializationRegistry registry = std::move(builder).Build();

  util::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<internal::ProtoParametersSerialization>(
          *parameters);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(OutputPrefixType::TINK));

  PrfBasedDeriverKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.prf_key_template().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_format.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
