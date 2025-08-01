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

#include "tink/keyderivation/prf_based_key_derivation_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/internal/internal_insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/keyderivation/prf_based_key_derivation_key.h"
#include "tink/keyderivation/prf_based_key_derivation_parameters.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/prf/aes_cmac_prf_key.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::google::crypto::tink::PrfBasedDeriverParams;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::Test;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey";
constexpr absl::string_view kPrfKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";
constexpr absl::string_view kDerivedKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";
constexpr absl::string_view kPrfKeyValue = "0123456789abcdef";

class PrfBasedKeyDerivationProtoSerializationTest : public Test {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(PrfBasedKeyDerivationProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());
}

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

KeyData GetAesCmacPrfKeyData() {
  google::crypto::tink::AesCmacPrfKey key;
  key.set_version(0);
  key.set_key_value("0123456789abcdef");
  KeyData key_data;
  key_data.set_type_url(kPrfKeyTypeUrl);
  key_data.set_value(key.SerializeAsString());
  key_data.set_key_material_type(KeyData::SYMMETRIC);
  return key_data;
}

AesCmacPrfParameters GetAesCmacPrfParameters() {
  absl::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(kPrfKeyValue.size());
  CHECK_OK(parameters);
  return *parameters;
}

AesCmacPrfKey GetAesCmacPrfKey() {
  absl::StatusOr<AesCmacPrfKey> key = AesCmacPrfKey::Create(
      RestrictedData(kPrfKeyValue, GetInsecureSecretKeyAccessInternal()),
      GetPartialKeyAccess());
  CHECK_OK(key);
  return *key;
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
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kTink);
  CHECK_OK(parameters);
  return *parameters;
}

TEST_F(PrfBasedKeyDerivationProtoSerializationTest, ParseParameters) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  PrfBasedDeriverKeyFormat key_format_proto;
  *key_format_proto.mutable_prf_key_template() = GetAesCmacPrfKeyTemplate();
  PrfBasedDeriverParams prf_based_deriver_params;
  *prf_based_deriver_params.mutable_derived_key_template() =
      derived_key_template;
  *key_format_proto.mutable_params() = prf_based_deriver_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl,
          static_cast<OutputPrefixTypeEnum>(
              derived_key_template.output_prefix_type()),
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
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

TEST_F(PrfBasedKeyDerivationProtoSerializationTest, SerializeParameters) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::KeyTemplateStruct& key_template =
      proto_serialization->GetKeyTemplateStruct();
  EXPECT_THAT(key_template.type_url, Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type, Eq(OutputPrefixTypeEnum::kTink));

  PrfBasedDeriverKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value), IsTrue());
  EXPECT_THAT(key_format.prf_key_template().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_format.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

TEST_F(PrfBasedKeyDerivationProtoSerializationTest, ParseKey) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  KeyTemplate derived_key_template = GetXChaCha20Poly1305KeyTemplate();

  google::crypto::tink::PrfBasedDeriverKey key_proto;
  key_proto.set_version(0);
  *key_proto.mutable_prf_key() = GetAesCmacPrfKeyData();
  *key_proto.mutable_params()->mutable_derived_key_template() =
      derived_key_template;

  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), GetInsecureSecretKeyAccessInternal());
  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyMaterialTypeEnum::kSymmetric,
          static_cast<OutputPrefixTypeEnum>(
              derived_key_template.output_prefix_type()),
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(123));
  EXPECT_THAT(
      (*key)->GetParameters().HasIdRequirement(),
      derived_key_template.output_prefix_type() != OutputPrefixType::RAW);

  absl::StatusOr<PrfBasedKeyDerivationParameters> expected_parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<PrfBasedKeyDerivationKey> expected_key =
      PrfBasedKeyDerivationKey::Create(*expected_parameters, GetAesCmacPrfKey(),
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(PrfBasedKeyDerivationProtoSerializationTest, SerializeKey) {
  ASSERT_THAT(RegisterPrfBasedKeyDerivationProtoSerialization(), IsOk());

  absl::StatusOr<PrfBasedKeyDerivationParameters> parameters =
      PrfBasedKeyDerivationParameters::Builder()
          .SetPrfParameters(GetAesCmacPrfParameters())
          .SetDerivedKeyParameters(GetXChaCha20Poly1305Parameters())
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<PrfBasedKeyDerivationKey> key =
      PrfBasedKeyDerivationKey::Create(*parameters, GetAesCmacPrfKey(),
                                       /*id_requirement=*/123,
                                       GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, GetInsecureSecretKeyAccessInternal());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kSymmetric));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(static_cast<OutputPrefixTypeEnum>(
                  GetXChaCha20Poly1305KeyTemplate().output_prefix_type())));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(123));

  google::crypto::tink::PrfBasedDeriverKey key_proto;
  key_proto.set_version(0);
  ASSERT_THAT(key_proto.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      GetInsecureSecretKeyAccessInternal())),
              IsTrue());
  EXPECT_THAT(key_proto.prf_key().type_url(), Eq(kPrfKeyTypeUrl));
  EXPECT_THAT(key_proto.params().derived_key_template().type_url(),
              Eq(kDerivedKeyTypeUrl));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
