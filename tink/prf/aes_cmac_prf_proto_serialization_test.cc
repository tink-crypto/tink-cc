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

#include "tink/prf/aes_cmac_prf_proto_serialization.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/prf/aes_cmac_prf_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_cmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCmacPrfKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

class AesCmacPrfProtoSerializationTest : public TestWithParam<int> {
 protected:
  AesCmacPrfProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(AesCmacPrfProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(AesCmacPrfProtoSerializationTestSuite,
                         AesCmacPrfProtoSerializationTest, Values(16, 32));

TEST_P(AesCmacPrfProtoSerializationTest, ParseParameters) {
  int key_size = GetParam();
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());

  AesCmacPrfKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(key_size);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());

  const AesCmacPrfParameters* parameters =
      dynamic_cast<const AesCmacPrfParameters*>(params->get());
  ASSERT_THAT(parameters, NotNull());
  EXPECT_THAT(parameters->KeySizeInBytes(), Eq(key_size));
}

TEST_F(AesCmacPrfProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse AesCmacPrfKeyFormat proto")));
}

using AesCmacPrfParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(
    AesCmacPrfParsePrefixTestSuite, AesCmacPrfParsePrefixTest,
    Values(OutputPrefixType::TINK, OutputPrefixType::CRUNCHY,
           OutputPrefixType::LEGACY, OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(AesCmacPrfParsePrefixTest, ParseParametersWithInvalidPrefixFails) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());

  AesCmacPrfKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(32);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, invalid_output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr(
                   "Output prefix type must be RAW for AesCmacPrfParameters")));
}

TEST_F(AesCmacPrfProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());

  AesCmacPrfKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  key_format_proto.set_key_size(32);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(AesCmacPrfProtoSerializationTest, SerializeParameters) {
  int key_size = GetParam();
  ASSERT_THAT(RegisterAesCmacPrfProtoSerialization(), IsOk());

  util::StatusOr<AesCmacPrfParameters> parameters =
      AesCmacPrfParameters::Create(key_size);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(OutputPrefixType::RAW));

  AesCmacPrfKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.key_size(), Eq(key_size));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
