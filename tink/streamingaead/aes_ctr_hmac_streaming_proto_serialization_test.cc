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

#include "tink/streamingaead/aes_ctr_hmac_streaming_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::AesCtrHmacStreamingParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacParams;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

struct TestCase {
  int key_size;
  int derived_key_size;
  AesCtrHmacStreamingParameters::HashType hkdf_hash_type;
  HashType proto_hkdf_hash_type;
  AesCtrHmacStreamingParameters::HashType hmac_hash_type;
  HashType proto_hmac_hash_type;
  int tag_size;
  int segment_size;
};

class AesCtrHmacStreamingProtoSerializationTest
    : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(AesCtrHmacStreamingProtoSerializationTest, RegisterTwiceSucceeds) {
  EXPECT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());
  EXPECT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacStreamingProtoSerializationTestSuite,
    AesCtrHmacStreamingProtoSerializationTest,
    Values(
        TestCase{
            /*key_size=*/19, /*derived_key_size=*/16,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*proto_hkdf_hash_type=*/HashType::SHA1,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*proto_hmac_hash_type=*/HashType::SHA1,
            /*tag_size=*/10, /*segment_size=*/1024},
        TestCase{
            /*key_size=*/19, /*derived_key_size=*/16,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha256,
            /*proto_hkdf_hash_type=*/HashType::SHA256,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha1,
            /*proto_hmac_hash_type=*/HashType::SHA1,
            /*tag_size=*/14, /*segment_size=*/1024 * 1024},
        TestCase{
            /*key_size=*/35, /*derived_key_size=*/32,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*proto_hkdf_hash_type=*/HashType::SHA512,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha256,
            /*proto_hmac_hash_type=*/HashType::SHA256,
            /*tag_size=*/16, /*segment_size=*/3 * 1024 * 1024},
        TestCase{
            /*key_size=*/35, /*derived_key_size=*/32,
            /*hkdf_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*proto_hkdf_hash_type=*/HashType::SHA512,
            /*hmac_hash_type=*/AesCtrHmacStreamingParameters::HashType::kSha512,
            /*proto_hmac_hash_type=*/HashType::SHA512,
            /*tag_size=*/64, /*segment_size=*/4 * 1024 * 1024}));

TEST_P(AesCtrHmacStreamingProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(test_case.tag_size);
  proto_hmac_params.set_hash(test_case.proto_hmac_hash_type);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(test_case.segment_size);
  proto_params.set_derived_key_size(test_case.derived_key_size);
  proto_params.set_hkdf_hash_type(test_case.proto_hkdf_hash_type);
  *proto_params.mutable_hmac_params() = proto_hmac_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(test_case.key_size);
  *format.mutable_params() = proto_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> expected =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

using AesCtrHmacStreamingParsePrefixTest = TestWithParam<OutputPrefixTypeEnum>;

INSTANTIATE_TEST_SUITE_P(AesCtrHmacStreamingParsePrefixTestSuite,
                         AesCtrHmacStreamingParsePrefixTest,
                         Values(OutputPrefixTypeEnum::kTink,
                                OutputPrefixTypeEnum::kCrunchy,
                                OutputPrefixTypeEnum::kLegacy,
                                OutputPrefixTypeEnum::kUnknownPrefix));

TEST_P(AesCtrHmacStreamingParsePrefixTest, ParseParametersWithIgnoredPrefix) {
  OutputPrefixTypeEnum ignored_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(16);
  proto_hmac_params.set_hash(HashType::SHA256);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::SHA256);
  *proto_params.mutable_hmac_params() = proto_hmac_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, ignored_output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  AesCtrHmacStreamingKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_key_size(32);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithoutStreamingParamsFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithoutHmacParamsFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  AesCtrHmacStreamingParams proto_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);
  *format.mutable_params() = proto_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithInvalidHkdfHashTypeFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(16);
  proto_hmac_params.set_hash(HashType::SHA256);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  *proto_params.mutable_hmac_params() = proto_hmac_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported proto hash type")));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseParametersWithInvalidHmacHashTypeFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(16);
  proto_hmac_params.set_hash(HashType::UNKNOWN_HASH);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::SHA256);
  *proto_params.mutable_hmac_params() = proto_hmac_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixTypeEnum::kRaw, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported proto hash type")));
}

TEST_P(AesCtrHmacStreamingProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(OutputPrefixTypeEnum::kRaw));

  AesCtrHmacStreamingKeyFormat format;
  ASSERT_THAT(format.ParseFromString(key_template.value()), IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.key_size(), Eq(test_case.key_size));

  ASSERT_THAT(format.has_params(), IsTrue());
  EXPECT_THAT(format.params().derived_key_size(),
              Eq(test_case.derived_key_size));
  EXPECT_THAT(format.params().ciphertext_segment_size(),
              Eq(test_case.segment_size));
  EXPECT_THAT(format.params().hkdf_hash_type(),
              Eq(test_case.proto_hkdf_hash_type));

  ASSERT_THAT(format.params().has_hmac_params(), IsTrue());
  EXPECT_THAT(format.params().hmac_params().tag_size(), Eq(test_case.tag_size));
  EXPECT_THAT(format.params().hmac_params().hash(),
              Eq(test_case.proto_hmac_hash_type));
}

TEST_P(AesCtrHmacStreamingProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(test_case.tag_size);
  proto_hmac_params.set_hash(test_case.proto_hmac_hash_type);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(test_case.segment_size);
  proto_params.set_derived_key_size(test_case.derived_key_size);
  proto_params.set_hkdf_hash_type(test_case.proto_hkdf_hash_type);
  *proto_params.mutable_hmac_params() = proto_hmac_params;

  std::string initial_key_material = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesCtrHmacStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  *key_proto.mutable_params() = proto_params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              OutputPrefixTypeEnum::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> expected_parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<AesCtrHmacStreamingKey> expected_key =
      AesCtrHmacStreamingKey::Create(
          *expected_parameters,
          RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              OutputPrefixTypeEnum::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesCtrHmacStreamingKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              OutputPrefixTypeEnum::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsing AesCtrHmacStreamingKey failed: only "
                                 "version 0 is accepted")));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseKeyWithMissingParamsFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesCtrHmacStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              OutputPrefixTypeEnum::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesCtrHmacStreamingParsePrefixTest,
       ParseKeyWithNonRawPrefixIgnoresPrefix) {
  OutputPrefixTypeEnum ignored_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  HmacParams proto_hmac_params;
  proto_hmac_params.set_tag_size(16);
  proto_hmac_params.set_hash(HashType::SHA256);
  AesCtrHmacStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::SHA256);
  *proto_params.mutable_hmac_params() = proto_hmac_params;
  AesCtrHmacStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;
  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesCtrHmacStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  *key_proto.mutable_params() = proto_params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              ignored_output_prefix_type,
                                              /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       ParseKeyWithoutSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesCtrHmacStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyMaterialTypeEnum::kSymmetric,
                                              OutputPrefixTypeEnum::kRaw,
                                              /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(AesCtrHmacStreamingProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHkdfHashType(test_case.hkdf_hash_type)
          .SetHmacHashType(test_case.hmac_hash_type)
          .SetHmacTagSizeInBytes(test_case.tag_size)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string initial_key_material = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters,
      RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
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
              Eq(OutputPrefixTypeEnum::kRaw));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::AesCtrHmacStreamingKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(initial_key_material));

  ASSERT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().derived_key_size(),
              Eq(test_case.derived_key_size));
  EXPECT_THAT(proto_key.params().ciphertext_segment_size(),
              Eq(test_case.segment_size));
  EXPECT_THAT(proto_key.params().hkdf_hash_type(),
              Eq(test_case.proto_hkdf_hash_type));

  ASSERT_THAT(proto_key.params().has_hmac_params(), IsTrue());
  EXPECT_THAT(proto_key.params().hmac_params().tag_size(),
              Eq(test_case.tag_size));
  EXPECT_THAT(proto_key.params().hmac_params().hash(),
              Eq(test_case.proto_hmac_hash_type));
}

TEST_F(AesCtrHmacStreamingProtoSerializationTest,
       SerializeKeyWithoutSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesCtrHmacStreamingProtoSerialization(), IsOk());

  absl::StatusOr<AesCtrHmacStreamingParameters> parameters =
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHkdfHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacHashType(AesCtrHmacStreamingParameters::HashType::kSha256)
          .SetHmacTagSizeInBytes(16)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string initial_key_material = Random::GetRandomBytes(19);
  absl::StatusOr<AesCtrHmacStreamingKey> key = AesCtrHmacStreamingKey::Create(
      *parameters,
      RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
