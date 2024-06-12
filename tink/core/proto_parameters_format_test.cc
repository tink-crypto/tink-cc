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
///////////////////////////////////////////////////////////////////////////////

#include "tink/proto_parameters_format.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/aes_cmac_proto_serialization.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacKeyFormat;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::Not;

class ProtoParametersFormatTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(RegisterAesCmacProtoSerialization(), IsOk());
  }
};

TEST_F(ProtoParametersFormatTest, SerializeAesCmacParameters) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::string> serialized_parameters =
      SerializeParametersToProtoFormat(*parameters);
  ASSERT_THAT(serialized_parameters, IsOk());

  KeyTemplate key_template;
  ASSERT_THAT(key_template.ParseFromString(*serialized_parameters), IsTrue());

  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::TINK));
  EXPECT_THAT(key_template.type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesCmacKey"));

  AesCmacKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().tag_size(), Eq(16));
}

TEST_F(ProtoParametersFormatTest, SerializeLegacyProtoParameters) {
  KeyTemplate key_template;
  key_template.set_value(std::string("\x00\x80", 2));
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("invalid_url");

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(serialization, IsOk());

  internal::LegacyProtoParameters legacy_proto_parameters(*serialization);
  util::StatusOr<std::string> serialized_parameters =
      SerializeParametersToProtoFormat(legacy_proto_parameters);
  ASSERT_THAT(serialized_parameters, IsOk());

  KeyTemplate serialized_key_template;
  ASSERT_THAT(serialized_key_template.ParseFromString(*serialized_parameters),
              IsTrue());

  EXPECT_THAT(serialized_key_template.output_prefix_type(),
              Eq(key_template.output_prefix_type()));
  EXPECT_THAT(serialized_key_template.type_url(), Eq(key_template.type_url()));
  EXPECT_THAT(serialized_key_template.value(), Eq(key_template.value()));
}

TEST_F(ProtoParametersFormatTest, ParseAesCmacKeyFormat) {
  AesCmacKeyFormat key_format;
  key_format.set_key_size(32);
  key_format.mutable_params()->set_tag_size(16);

  KeyTemplate key_template;
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCmacKey");
  key_template.set_value(key_format.SerializeAsString());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters, IsOk());

  util::StatusOr<AesCmacParameters> expected_parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(expected_parameters, IsOk());

  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(ProtoParametersFormatTest, ParseLegacyProtoParameters) {
  KeyTemplate key_template;
  key_template.set_value(std::string("\x00\x80", 2));
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url("invalid_url");  // Should parse into legacy proto.

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters, IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(key_template);
  ASSERT_THAT(serialization, IsOk());

  internal::LegacyProtoParameters expected_parameters(*serialization);
  EXPECT_THAT(**parsed_parameters, Eq(expected_parameters));
}

TEST_F(ProtoParametersFormatTest, ParseInvalidKeyTemplateFails) {
  ASSERT_THAT(
      ParseParametersFromProtoFormat("invalid_key_template").status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Failed to parse proto parameters into key template")));
}

TEST_F(ProtoParametersFormatTest, ParseInvalidAesCmacKeyFormatFails) {
  AesCmacKeyFormat key_format;
  key_format.set_key_size(37);  // Invalid key size.
  key_format.mutable_params()->set_tag_size(16);

  KeyTemplate key_template;
  key_template.set_output_prefix_type(OutputPrefixType::TINK);
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.AesCmacKey");
  key_template.set_value(key_format.SerializeAsString());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(key_template.SerializeAsString());
  ASSERT_THAT(parsed_parameters.status(), Not(IsOk()));
}

TEST_F(ProtoParametersFormatTest, SerializeAndParse) {
  util::StatusOr<AesCmacParameters> parameters =
      AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                /*cryptographic_tag_size_in_bytes=*/16,
                                AesCmacParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::string> serialized_parameters =
      SerializeParametersToProtoFormat(*parameters);
  ASSERT_THAT(serialized_parameters, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      ParseParametersFromProtoFormat(*serialized_parameters);
  ASSERT_THAT(parsed_parameters, IsOk());

  EXPECT_THAT(**parsed_parameters, Eq(*parameters));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
