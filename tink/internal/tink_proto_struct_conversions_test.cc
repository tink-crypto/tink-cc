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

#include "tink/internal/tink_proto_struct_conversions.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/util/secret_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;

TEST(ToKeyTemplateTPTest, Works) {
  KeyTemplate key_template;
  key_template.set_type_url("type_url");
  key_template.set_value("value");
  key_template.set_output_prefix_type(OutputPrefixType::TINK);

  KeyTemplateTP key_template_tp = ToKeyTemplateTP(key_template);

  EXPECT_THAT(key_template_tp.type_url(), Eq("type_url"));
  EXPECT_THAT(key_template_tp.value(), Eq("value"));
  EXPECT_THAT(key_template_tp.output_prefix_type(),
              Eq(OutputPrefixTypeTP::kTink));
}

TEST(ToKeyTemplateTPTest, WorksWithRaw) {
  KeyTemplate key_template;
  key_template.set_type_url("type_url_raw");
  key_template.set_value("value_raw");
  key_template.set_output_prefix_type(OutputPrefixType::RAW);

  KeyTemplateTP key_template_tp = ToKeyTemplateTP(key_template);

  EXPECT_THAT(key_template_tp.type_url(), Eq("type_url_raw"));
  EXPECT_THAT(key_template_tp.value(), Eq("value_raw"));
  EXPECT_THAT(key_template_tp.output_prefix_type(),
              Eq(OutputPrefixTypeTP::kRaw));
}

TEST(FromKeyTemplateTPTest, Works) {
  KeyTemplateTP key_template_tp;
  key_template_tp.set_type_url("type_url");
  key_template_tp.set_value("value");
  key_template_tp.set_output_prefix_type(OutputPrefixTypeTP::kTink);

  KeyTemplate key_template = ToProtoKeyTemplate(key_template_tp);

  EXPECT_THAT(key_template.type_url(), Eq("type_url"));
  EXPECT_THAT(key_template.value(), Eq("value"));
  EXPECT_THAT(key_template.output_prefix_type(), Eq(OutputPrefixType::TINK));
}

TEST(KeyTemplateTPConversionTest, RoundTrip) {
  KeyTemplate key_template;
  key_template.set_type_url("some arbitrary type url");
  key_template.set_value("some arbitrary value");
  key_template.set_output_prefix_type(OutputPrefixType::LEGACY);

  KeyTemplate produced_template =
      ToProtoKeyTemplate(ToKeyTemplateTP(key_template));
  EXPECT_THAT(produced_template.type_url(), Eq(key_template.type_url()));
  EXPECT_THAT(produced_template.value(), Eq(key_template.value()));
  EXPECT_THAT(produced_template.output_prefix_type(),
              Eq(key_template.output_prefix_type()));
}

TEST(ToKeyDataTPTest, Works) {
  KeyData key_data;
  key_data.set_type_url("type_url");
  key_data.set_value("value");
  key_data.set_key_material_type(KeyData::SYMMETRIC);

  KeyDataTP key_data_tp = ToKeyDataTP(key_data);

  EXPECT_THAT(key_data_tp.type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key_data_tp.value()), Eq("value"));
  EXPECT_THAT(key_data_tp.key_material_type(),
              Eq(KeyMaterialTypeTP::kSymmetric));
}

TEST(ToKeyDataTPTest, WorksWithAsymmetric) {
  KeyData key_data;
  key_data.set_type_url("type_url_asymmetric");
  key_data.set_value("value_asymmetric");
  key_data.set_key_material_type(KeyData::ASYMMETRIC_PRIVATE);

  KeyDataTP key_data_tp = ToKeyDataTP(key_data);

  EXPECT_THAT(key_data_tp.type_url(), Eq("type_url_asymmetric"));
  EXPECT_THAT(util::SecretDataAsStringView(key_data_tp.value()),
              Eq("value_asymmetric"));
  EXPECT_THAT(key_data_tp.key_material_type(),
              Eq(KeyMaterialTypeTP::kAsymmetricPrivate));
}

TEST(FromKeyDataTPTest, Works) {
  KeyDataTP key_data_tp;
  key_data_tp.set_type_url("type_url");
  key_data_tp.set_value("value");
  key_data_tp.set_key_material_type(KeyMaterialTypeTP::kSymmetric);

  KeyData key_data = ToProtoKeyData(key_data_tp);

  EXPECT_THAT(key_data.type_url(), Eq("type_url"));
  EXPECT_THAT(key_data.value(), Eq("value"));
  EXPECT_THAT(key_data.key_material_type(), Eq(KeyData::SYMMETRIC));
}

TEST(KeyDataTPConversionTest, RoundTrip) {
  KeyData key_data;
  key_data.set_type_url("some arbitrary type url");
  key_data.set_value("some arbitrary value");
  key_data.set_key_material_type(KeyData::REMOTE);

  KeyData produced_data = ToProtoKeyData(ToKeyDataTP(key_data));
  EXPECT_THAT(produced_data.type_url(), Eq(key_data.type_url()));
  EXPECT_THAT(produced_data.value(), Eq(key_data.value()));
  EXPECT_THAT(produced_data.key_material_type(),
              Eq(key_data.key_material_type()));
}

TEST(ToKeyTPTest, Works) {
  Keyset::Key key;
  key.mutable_key_data()->set_type_url("type_url");
  key.mutable_key_data()->set_value("value");
  key.mutable_key_data()->set_key_material_type(KeyData::SYMMETRIC);
  key.set_status(KeyStatusType::ENABLED);
  key.set_key_id(123);
  key.set_output_prefix_type(OutputPrefixType::TINK);

  KeysetTP::KeyTP key_tp = ToKeyTP(key);

  EXPECT_THAT(key_tp.key_data().type_url(), Eq("type_url"));
  EXPECT_THAT(util::SecretDataAsStringView(key_tp.key_data().value()),
              Eq("value"));
  EXPECT_THAT(key_tp.key_data().key_material_type(),
              Eq(KeyMaterialTypeTP::kSymmetric));
  EXPECT_THAT(key_tp.status(), Eq(KeyStatusTypeTP::kEnabled));
  EXPECT_THAT(key_tp.key_id(), Eq(123));
  EXPECT_THAT(key_tp.output_prefix_type(), Eq(OutputPrefixTypeTP::kTink));
}

TEST(ToProtoKeyTest, Works) {
  KeysetTP::KeyTP key_tp;
  key_tp.mutable_key_data()->set_type_url("type_url");
  key_tp.mutable_key_data()->set_value("value");
  key_tp.mutable_key_data()->set_key_material_type(
      KeyMaterialTypeTP::kSymmetric);
  key_tp.set_status(KeyStatusTypeTP::kEnabled);
  key_tp.set_key_id(123);
  key_tp.set_output_prefix_type(OutputPrefixTypeTP::kTink);

  Keyset::Key key = ToProtoKey(key_tp);

  EXPECT_THAT(key.key_data().type_url(), Eq("type_url"));
  EXPECT_THAT(key.key_data().value(), Eq("value"));
  EXPECT_THAT(key.key_data().key_material_type(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(key.status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT(key.key_id(), Eq(123));
  EXPECT_THAT(key.output_prefix_type(), Eq(OutputPrefixType::TINK));
}

TEST(KeyTPConversionTest, RoundTrip) {
  Keyset::Key key;
  key.mutable_key_data()->set_type_url("type_url");
  key.mutable_key_data()->set_value("value");
  key.mutable_key_data()->set_key_material_type(KeyData::ASYMMETRIC_PRIVATE);
  key.set_status(KeyStatusType::DISABLED);
  key.set_key_id(456);
  key.set_output_prefix_type(OutputPrefixType::RAW);

  Keyset::Key produced_key = ToProtoKey(ToKeyTP(key));
  EXPECT_THAT(produced_key.key_data().type_url(),
              Eq(key.key_data().type_url()));
  EXPECT_THAT(produced_key.key_data().value(), Eq(key.key_data().value()));
  EXPECT_THAT(produced_key.key_data().key_material_type(),
              Eq(key.key_data().key_material_type()));
  EXPECT_THAT(produced_key.status(), Eq(key.status()));
  EXPECT_THAT(produced_key.key_id(), Eq(key.key_id()));
  EXPECT_THAT(produced_key.output_prefix_type(), Eq(key.output_prefix_type()));
}

TEST(KeyTPConversionTest, KeyDataNotSetRoundTrip) {
  Keyset::Key key;
  key.set_status(KeyStatusType::DESTROYED);
  key.set_key_id(789);
  key.set_output_prefix_type(OutputPrefixType::LEGACY);

  Keyset::Key produced_key = ToProtoKey(ToKeyTP(key));
  EXPECT_THAT(produced_key.key_data().type_url(),
              Eq(key.key_data().type_url()));
  EXPECT_THAT(produced_key.key_data().value(), Eq(key.key_data().value()));
  EXPECT_THAT(produced_key.key_data().key_material_type(),
              Eq(key.key_data().key_material_type()));
  EXPECT_THAT(produced_key.status(), Eq(key.status()));
  EXPECT_THAT(produced_key.key_id(), Eq(key.key_id()));
  EXPECT_THAT(produced_key.output_prefix_type(), Eq(key.output_prefix_type()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
