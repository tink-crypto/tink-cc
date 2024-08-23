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

#include "tink/prf/hmac_prf_proto_serialization.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/prf/hmac_prf_parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/hmac_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacPrfKeyFormat;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HmacPrfKey";

struct TestCase {
  int key_size;
  HmacPrfParameters::HashType hash_type;
  HashType proto_hash_type;
};

class HmacPrfProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  HmacPrfProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    HmacPrfParametersCreateTestSuite, HmacPrfProtoSerializationTest,
    Values(TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha1,
                    HashType::SHA1},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha224,
                    HashType::SHA224},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha256,
                    HashType::SHA256},
           TestCase{/*key_size=*/16, HmacPrfParameters::HashType::kSha384,
                    HashType::SHA384},
           TestCase{/*key_size=*/32, HmacPrfParameters::HashType::kSha512,
                    HashType::SHA512}));

TEST_F(HmacPrfProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());
}

TEST_P(HmacPrfProtoSerializationTest, ParseParameters) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(test_case.key_size);
  proto_key_format.mutable_params()->set_hash(test_case.proto_hash_type);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(), IsFalse());

  util::StatusOr<HmacPrfParameters> expected_parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
  ASSERT_THAT(expected_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(HmacPrfProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse HmacPrfKeyFormat proto")));
}

using HmacPrfParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(HmacPrfParsePrefixTestSuite, HmacPrfParsePrefixTest,
                         Values(OutputPrefixType::TINK,
                                OutputPrefixType::CRUNCHY,
                                OutputPrefixType::LEGACY,
                                OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(HmacPrfParsePrefixTest, ParseParametersWithInvalidPrefixFails) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, invalid_output_prefix_type,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Output prefix type must be RAW for HmacPrfParameters")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  HmacPrfKeyFormat proto_key_format;
  proto_key_format.set_version(1);  // invalid version
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(HmacPrfProtoSerializationTest, ParseParametersWithUnknownHashTypeFails) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  HmacPrfKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.set_version(0);
  key_format_proto.mutable_params()->set_hash(HashType::UNKNOWN_HASH);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine HashType")));
}

TEST_P(HmacPrfProtoSerializationTest, SerializeParameters) {
  ASSERT_THAT(RegisterHmacPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  util::StatusOr<HmacPrfParameters> parameters =
      HmacPrfParameters::Create(test_case.key_size, test_case.hash_type);
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

  HmacPrfKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().hash(), Eq(test_case.proto_hash_type));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
