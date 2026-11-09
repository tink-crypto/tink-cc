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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "proto/test_proto.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestProto;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct ParametersTestCase {
  TestOnlyParameters::Variant variant;
  bool has_id_requirement;
};

using TestOnlyParametersVariantTest = TestWithParam<ParametersTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlyParametersVariantTestSuite, TestOnlyParametersVariantTest,
    Values(ParametersTestCase{TestOnlyParameters::Variant::kTink, true},
           ParametersTestCase{TestOnlyParameters::Variant::kCrunchy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kLegacy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kNoPrefix, false}));

TEST_P(TestOnlyParametersVariantTest, Create) {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetVariant(), Eq(GetParam().variant));
  EXPECT_THAT(parameters->HasIdRequirement(),
              Eq(GetParam().has_id_requirement));
}

TEST_P(TestOnlyParametersVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTestOnlyKeyTypeUrl));
  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(**serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*parameters));
}

TEST(TestOnlyParametersTest, ParseInvalidKeyFormatFails) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  TestProto wrong_key_size;
  wrong_key_size.set_num(kTestOnlyKeySizeInBytes + 1);
  TestProto unexpected_field;
  unexpected_field.set_num(kTestOnlyKeySizeInBytes);
  unexpected_field.set_str("unexpected");

  for (const TestProto& key_format : {wrong_key_size, unexpected_field}) {
    KeyTemplate key_template;
    key_template.set_type_url(kTestOnlyKeyTypeUrl);
    key_template.set_output_prefix_type(OutputPrefixType::TINK);
    key_template.set_value(key_format.SerializeAsString());
    absl::StatusOr<ProtoParametersSerialization> serialization =
        ProtoParametersSerialization::Create(key_template);
    ASSERT_THAT(serialization, IsOk());

    EXPECT_THAT(MutableSerializationRegistry::GlobalInstance().ParseParameters(
                    *serialization),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST(TestOnlyParametersTest, InvalidVariantFails) {
  EXPECT_THAT(TestOnlyParameters::Create(
                  TestOnlyParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements),
              Not(IsOk()));
}

TEST(TestOnlyParametersTest, ParametersWithDifferentVariantsAreNotEqual) {
  absl::StatusOr<TestOnlyParameters> tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> other_tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(other_tink_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> crunchy_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_parameters, IsOk());

  EXPECT_THAT(*tink_parameters == *other_tink_parameters, IsTrue());
  EXPECT_THAT(*tink_parameters != *crunchy_parameters, IsTrue());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
