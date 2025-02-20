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

#include "tink/prf/hkdf_prf_proto_serialization.h"

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
#include "tink/prf/hkdf_prf_key.h"
#include "tink/prf/hkdf_prf_parameters.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::google::crypto::tink::HkdfPrfParams;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

constexpr absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

struct TestCase {
  int key_size;
  HkdfPrfParameters::HashType hash_type;
  HashType proto_hash_type;
  absl::optional<std::string> salt;
};

class HkdfPrfProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  HkdfPrfProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    HkdfPrfParametersCreateTestSuite, HkdfPrfProtoSerializationTest,
    Values(TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha1,
                    HashType::SHA1, /*salt=*/absl::nullopt},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha224,
                    HashType::SHA224,
                    /*salt=*/test::HexDecodeOrDie("00010203040506")},
           TestCase{/*key_size=*/16, HkdfPrfParameters::HashType::kSha256,
                    HashType::SHA256,
                    /*salt=*/test::HexDecodeOrDie("00010203040506070809")},
           TestCase{
               /*key_size=*/32, HkdfPrfParameters::HashType::kSha384,
               HashType::SHA384,
               /*salt=*/test::HexDecodeOrDie("000102030405060708090a0b0c")},
           TestCase{/*key_size=*/32, HkdfPrfParameters::HashType::kSha512,
                    HashType::SHA512,
                    /*salt=*/
                    test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f")}));

TEST_F(HkdfPrfProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());
}

TEST_P(HkdfPrfProtoSerializationTest, ParseParameters) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();

  HkdfPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(test_case.key_size);

  HkdfPrfParams params;
  params.set_hash(test_case.proto_hash_type);
  if (test_case.salt.has_value()) {
    params.set_salt(*test_case.salt);
  }
  *proto_key_format.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(), IsFalse());

  absl::StatusOr<HkdfPrfParameters> expected_parameters =
      HkdfPrfParameters::Create(test_case.key_size, test_case.hash_type,
                                test_case.salt);
  ASSERT_THAT(expected_parameters, IsOk());
  ASSERT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(HkdfPrfProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse HkdfPrfKeyFormat proto")));
}

using HkdfPrfParsePrefixTest = TestWithParam<OutputPrefixType>;

INSTANTIATE_TEST_SUITE_P(HkdfPrfParsePrefixTestSuite, HkdfPrfParsePrefixTest,
                         Values(OutputPrefixType::TINK,
                                OutputPrefixType::CRUNCHY,
                                OutputPrefixType::LEGACY,
                                OutputPrefixType::UNKNOWN_PREFIX));

TEST_P(HkdfPrfParsePrefixTest, ParseParametersWithInvalidPrefixFails) {
  OutputPrefixType invalid_output_prefix_type = GetParam();
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  HkdfPrfKeyFormat proto_key_format;
  proto_key_format.set_version(0);
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, invalid_output_prefix_type,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(
      params.status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Output prefix type must be RAW for HkdfPrfParameters")));
}

TEST_F(HkdfPrfProtoSerializationTest, ParseParametersWithInvalidVersionFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  HkdfPrfKeyFormat proto_key_format;
  proto_key_format.set_version(1);  // invalid version
  proto_key_format.set_key_size(16);
  proto_key_format.mutable_params()->set_hash(HashType::SHA256);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          proto_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(HkdfPrfProtoSerializationTest, ParseParametersWithUnknownHashTypeFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  HkdfPrfKeyFormat key_format_proto;
  key_format_proto.set_key_size(16);
  key_format_proto.set_version(0);
  key_format_proto.mutable_params()->set_hash(HashType::UNKNOWN_HASH);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Could not determine HashType")));
}

TEST_P(HkdfPrfProtoSerializationTest, SerializeParameters) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  absl::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      test_case.key_size, test_case.hash_type, test_case.salt);
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
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(OutputPrefixType::RAW));

  HkdfPrfKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.version(), Eq(0));
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
  EXPECT_THAT(key_format.params().hash(), Eq(test_case.proto_hash_type));
  if (test_case.salt.has_value()) {
    EXPECT_THAT(key_format.params().salt(), Eq(*test_case.salt));
  }
}

TEST_P(HkdfPrfProtoSerializationTest, ParseKey) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  HkdfPrfParams proto_params;
  proto_params.set_hash(test_case.proto_hash_type);
  if (test_case.salt.has_value()) {
    proto_params.set_salt(*test_case.salt);
  }
  google::crypto::tink::HkdfPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  *key_proto.mutable_params() = proto_params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(), IsFalse());

  absl::StatusOr<HkdfPrfParameters> expected_parameters =
      HkdfPrfParameters::Create(test_case.key_size, test_case.hash_type,
                                test_case.salt);
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<HkdfPrfKey> expected_key = HkdfPrfKey::Create(
      *expected_parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(HkdfPrfProtoSerializationTest, ParseKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Not enough data to read kFixed64")));
}

TEST_P(HkdfPrfParsePrefixTest, ParseKeyWithInvalidPrefixFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  OutputPrefixType invalid_output_prefix_type = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HkdfPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(kTypeUrl, serialized_key,
                                              KeyData::SYMMETRIC,
                                              invalid_output_prefix_type,
                                              /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());
  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      key.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Output prefix type must be RAW for HkdfPrfKey")));
}

TEST_F(HkdfPrfProtoSerializationTest, ParseKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HkdfPrfKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied,
                                     HasSubstr("SecretKeyAccess is required")));
}

TEST_F(HkdfPrfProtoSerializationTest, ParseKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  google::crypto::tink::HkdfPrfKey key_proto;
  key_proto.set_version(1);  // Invalid version number.
  key_proto.set_key_value(raw_key_bytes);
  key_proto.mutable_params()->set_hash(HashType::SHA256);
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kTypeUrl, serialized_key, KeyData::SYMMETRIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_P(HkdfPrfProtoSerializationTest, SerializeKey) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  TestCase test_case = GetParam();

  std::string raw_key_bytes = Random::GetRandomBytes(test_case.key_size);
  absl::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      test_case.key_size, test_case.hash_type, test_case.salt);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
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
  EXPECT_THAT(proto_serialization->KeyMaterialType(), Eq(KeyData::SYMMETRIC));
  EXPECT_THAT(proto_serialization->GetOutputPrefixType(),
              Eq(OutputPrefixType::RAW));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(absl::nullopt));

  google::crypto::tink::HkdfPrfKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());
  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.key_value(), Eq(raw_key_bytes));
  EXPECT_THAT(proto_key.params().hash(), Eq(test_case.proto_hash_type));
  if (test_case.salt.has_value()) {
    EXPECT_THAT(proto_key.params().salt(), Eq(*test_case.salt));
  }
}

TEST_F(HkdfPrfProtoSerializationTest, SerializeKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterHkdfPrfProtoSerialization(), IsOk());

  std::string raw_key_bytes = Random::GetRandomBytes(16);
  absl::StatusOr<HkdfPrfParameters> parameters = HkdfPrfParameters::Create(
      /*key_size_in_bytes=*/16, HkdfPrfParameters::HashType::kSha256,
      /*salt=*/absl::nullopt);
  ASSERT_THAT(parameters, IsOk());
  absl::StatusOr<HkdfPrfKey> key = HkdfPrfKey::Create(
      *parameters,
      RestrictedData(raw_key_bytes, InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  EXPECT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("SecretKeyAccess is required")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
