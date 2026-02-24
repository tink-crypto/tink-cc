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
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

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

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
