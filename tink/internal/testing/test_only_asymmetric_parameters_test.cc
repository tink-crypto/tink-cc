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

#include "tink/internal/testing/test_only_asymmetric_parameters.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/parameters.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestOnlyKeyFormat;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::Values;

struct ParametersTestCase {
  TestOnlyAsymmetricParameters::Variant variant;
  bool has_id_requirement;
};

using TestOnlyAsymmetricParametersVariantTest =
    TestWithParam<ParametersTestCase>;

INSTANTIATE_TEST_SUITE_P(
    TestOnlyAsymmetricParametersVariantTestSuite,
    TestOnlyAsymmetricParametersVariantTest,
    Values(ParametersTestCase{TestOnlyParameters::Variant::kTink, true},
           ParametersTestCase{TestOnlyParameters::Variant::kCrunchy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kLegacy, true},
           ParametersTestCase{TestOnlyParameters::Variant::kNoPrefix, false}));

TEST_P(TestOnlyAsymmetricParametersVariantTest, Create) {
  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  EXPECT_THAT(parameters->GetVariant(), Eq(GetParam().variant));
  EXPECT_THAT(parameters->HasIdRequirement(),
              Eq(GetParam().has_id_requirement));
}

TEST_P(TestOnlyAsymmetricParametersVariantTest, ProtoSerializationRoundTrip) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  MutableSerializationRegistry& registry =
      MutableSerializationRegistry::GlobalInstance();

  absl::StatusOr<TestOnlyAsymmetricParameters> parameters =
      TestOnlyAsymmetricParameters::Create(GetParam().variant);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeParameters<ProtoParametersSerialization>(*parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq(kTestOnlyPrivateKeyTypeUrl));
  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      registry.ParseParameters(**serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*parameters));
}

TEST(TestOnlyAsymmetricParametersTest, ParseInvalidKeyFormatFails) {
  ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
  TestOnlyKeyFormat too_large_key_size;
  too_large_key_size.set_key_size(kTestOnlyKeySizeInBytes + 1);
  TestOnlyKeyFormat too_small_key_size;
  too_small_key_size.set_key_size(kTestOnlyKeySizeInBytes - 1);

  for (const TestOnlyKeyFormat& key_format :
       {too_large_key_size, too_small_key_size}) {
    KeyTemplate key_template;
    key_template.set_type_url(kTestOnlyPrivateKeyTypeUrl);
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

TEST(TestOnlyAsymmetricParametersTest, InvalidVariantFails) {
  EXPECT_THAT(TestOnlyAsymmetricParameters::Create(
                  TestOnlyParameters::Variant::
                      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements),
              Not(IsOk()));
}

TEST(TestOnlyAsymmetricParametersTest, Equality) {
  absl::StatusOr<TestOnlyAsymmetricParameters> tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> other_tink_parameters =
      TestOnlyAsymmetricParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(other_tink_parameters, IsOk());
  absl::StatusOr<TestOnlyAsymmetricParameters> crunchy_parameters =
      TestOnlyAsymmetricParameters::Create(
          TestOnlyParameters::Variant::kCrunchy);
  ASSERT_THAT(crunchy_parameters, IsOk());
  absl::StatusOr<TestOnlyParameters> symmetric_tink_parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(symmetric_tink_parameters, IsOk());

  EXPECT_THAT(*tink_parameters == *other_tink_parameters, IsTrue());
  EXPECT_THAT(*tink_parameters != *crunchy_parameters, IsTrue());
  EXPECT_THAT(*tink_parameters != *symmetric_tink_parameters, IsTrue());
  EXPECT_THAT(*symmetric_tink_parameters != *tink_parameters, IsTrue());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
