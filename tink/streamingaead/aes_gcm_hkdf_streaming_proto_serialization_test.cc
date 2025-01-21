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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using ::google::crypto::tink::AesGcmHkdfStreamingParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

struct TestCase {
  int key_size;
  int derived_key_size;
  AesGcmHkdfStreamingParameters::HashType hash_type;
  HashType proto_hash_type;
  int segment_size;
};

class AesGcmHkdfStreamingProtoSerializationTest
    : public TestWithParam<TestCase> {
 protected:
  AesGcmHkdfStreamingProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(AesGcmHkdfStreamingProtoSerializationTest, RegisterTwiceSucceeds) {
  EXPECT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());
  EXPECT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmHkdfStreamingProtoSerializationTestSuite,
    AesGcmHkdfStreamingProtoSerializationTest,
    Values(
        TestCase{/*key_size=*/19, /*derived_key_size=*/16,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha1,
                 /*proto_hash_type=*/HashType::SHA1, /*segment_size=*/1024},
        TestCase{/*key_size=*/19, /*derived_key_size=*/16,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha256,
                 /*proto_hash_type=*/HashType::SHA256,
                 /*segment_size=*/1024 * 1024},
        TestCase{/*key_size=*/35, /*derived_key_size=*/32,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha512,
                 /*proto_hash_type=*/HashType::SHA512,
                 /*segment_size=*/3 * 1024 * 1024},
        TestCase{/*key_size=*/35, /*derived_key_size=*/32,
                 /*hash_type=*/AesGcmHkdfStreamingParameters::HashType::kSha512,
                 /*proto_hash_type=*/HashType::SHA512,
                 /*segment_size=*/4 * 1024 * 1024}));

TEST_P(AesGcmHkdfStreamingProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(test_case.segment_size);
  proto_params.set_derived_key_size(test_case.derived_key_size);
  proto_params.set_hkdf_hash_type(test_case.proto_hash_type);
  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(test_case.key_size);
  *format.mutable_params() = proto_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed, IsOk());

  util::StatusOr<AesGcmHkdfStreamingParameters> expected =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(expected, IsOk());
  EXPECT_THAT(**parsed, Eq(*expected));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

using AesGcmHkdfStreamingParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(
    AesGcmHkdfStreamingParsePrefixTestSuite, AesGcmHkdfStreamingParsePrefixTest,
    Values(OutputPrefixType::TINK, OutputPrefixType::CRUNCHY,
           OutputPrefixType::LEGACY, OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(AesGcmHkdfStreamingParsePrefixTest, ParseParametersWithIgnoredPrefix) {
  OutputPrefixType ignored_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::SHA256);
  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, ignored_output_prefix_type, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(1);  // Invalid version number.
  format.set_key_size(32);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsing AesGcmHkdfStreamingKeyFormat failed: "
                                 "only version 0 is accepted")));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseParametersWithoutStreamingParamsFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(32);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseParametersWithInvalidHashTypeFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::UNKNOWN_HASH);
  AesGcmHkdfStreamingKeyFormat format;
  format.set_version(0);
  format.set_key_size(35);
  *format.mutable_params() = proto_params;

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmHkdfStreamingProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  util::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
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

  AesGcmHkdfStreamingKeyFormat format;
  ASSERT_THAT(
      format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(format.version(), Eq(0));
  EXPECT_THAT(format.key_size(), Eq(test_case.key_size));

  ASSERT_THAT(format.has_params(), IsTrue());
  EXPECT_THAT(format.params().derived_key_size(),
              Eq(test_case.derived_key_size));
  EXPECT_THAT(format.params().ciphertext_segment_size(),
              Eq(test_case.segment_size));
  EXPECT_THAT(format.params().hkdf_hash_type(), Eq(test_case.proto_hash_type));
}

TEST_P(AesGcmHkdfStreamingProtoSerializationTest, ParseKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(test_case.segment_size);
  proto_params.set_derived_key_size(test_case.derived_key_size);
  proto_params.set_hkdf_hash_type(test_case.proto_hash_type);

  std::string initial_key_material = Random::GetRandomBytes(test_case.key_size);
  google::crypto::tink::AesGcmHkdfStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  *key_proto.mutable_params() = proto_params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key, IsOk());

  util::StatusOr<AesGcmHkdfStreamingParameters> expected_parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  util::StatusOr<AesGcmHkdfStreamingKey> expected_key =
      AesGcmHkdfStreamingKey::Create(
          *expected_parameters,
          RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT(**parsed_key, Eq(*expected_key));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesGcmHkdfStreamingKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Parsing AesGcmHkdfStreamingKey failed: only "
                                 "version 0 is accepted")));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseKeyWithMissingParamsFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesGcmHkdfStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmHkdfStreamingParsePrefixTest,
       ParseKeyWithNonRawPrefixIgnoresPrefix) {
  OutputPrefixType ignored_output_prefix_type = GetParam();
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  AesGcmHkdfStreamingParams proto_params;
  proto_params.set_ciphertext_segment_size(1024 * 1024);
  proto_params.set_derived_key_size(32);
  proto_params.set_hkdf_hash_type(HashType::SHA256);

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesGcmHkdfStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  *key_proto.mutable_params() = proto_params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyData::SYMMETRIC,
                                              ignored_output_prefix_type,
                                              /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       ParseKeyWithoutSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  std::string initial_key_material = Random::GetRandomBytes(32);
  google::crypto::tink::AesGcmHkdfStreamingKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(initial_key_material);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  util::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_P(AesGcmHkdfStreamingProtoSerializationTest, SerializeKey) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  util::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(test_case.key_size)
          .SetDerivedKeySizeInBytes(test_case.derived_key_size)
          .SetHashType(test_case.hash_type)
          .SetCiphertextSegmentSizeInBytes(test_case.segment_size)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string initial_key_material = Random::GetRandomBytes(test_case.key_size);
  util::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters,
      RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(OutputPrefixType::RAW));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::AesGcmHkdfStreamingKey proto_key;
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
              Eq(test_case.proto_hash_type));
}

TEST_F(AesGcmHkdfStreamingProtoSerializationTest,
       SerializeKeyWithoutSecretKeyAccessFails) {
  ASSERT_THAT(RegisterAesGcmHkdfStreamingProtoSerialization(), IsOk());

  util::StatusOr<AesGcmHkdfStreamingParameters> parameters =
      AesGcmHkdfStreamingParameters::Builder()
          .SetKeySizeInBytes(19)
          .SetDerivedKeySizeInBytes(16)
          .SetHashType(AesGcmHkdfStreamingParameters::HashType::kSha256)
          .SetCiphertextSegmentSizeInBytes(1024)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  std::string initial_key_material = Random::GetRandomBytes(19);
  util::StatusOr<AesGcmHkdfStreamingKey> key = AesGcmHkdfStreamingKey::Create(
      *parameters,
      RestrictedData(initial_key_material, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
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
