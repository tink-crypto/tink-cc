// Copyright 2023 Google LLC
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
#include "tink/signature/rsa_ssa_pss_proto_serialization.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/tink_proto_structs.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/testing/equals_proto_key_serialization.h"
#include "tink/internal/testing/field_with_number.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::internal::ProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::EqualsProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssParams;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  RsaSsaPssParameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  RsaSsaPssParameters::HashType hash_type;
  HashType proto_hash_type;
  int modulus_size_in_bits;
  int salt_length_in_bytes;
  absl::optional<int> id;
  std::string output_prefix;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";

class RsaSsaPssProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(RsaSsaPssProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPssProtoSerializationTestSuite, RsaSsaPssProtoSerializationTest,
    Values(TestCase{RsaSsaPssParameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink,
                    RsaSsaPssParameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*salt_length_in_bytes=*/0,
                    /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPssParameters::Variant::kCrunchy,
                    OutputPrefixTypeEnum::kCrunchy,
                    RsaSsaPssParameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*salt_length_in_bytes=*/32,
                    /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPssParameters::Variant::kLegacy,
                    OutputPrefixTypeEnum::kLegacy,
                    RsaSsaPssParameters::HashType::kSha384, HashType::SHA384,
                    /*modulus_size=*/3072, /*salt_length_in_bytes*/ 48,
                    /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPssParameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw,
                    RsaSsaPssParameters::HashType::kSha512, HashType::SHA512,
                    /*modulus_size=*/3072, /*salt_length_in_bytes=*/64,
                    /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPssProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
  key_format_proto.set_public_exponent(kF4Str);

  RsaSsaPssParams params;
  params.set_sig_hash(test_case.proto_hash_type);
  params.set_mgf1_hash(test_case.proto_hash_type);
  params.set_salt_length(test_case.salt_length_in_bytes);
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, test_case.output_prefix_type,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parameters, IsOk());

  EXPECT_THAT((*parameters)->HasIdRequirement(), test_case.id.has_value());
  const RsaSsaPssParameters* rsa_ssa_pss_parameters =
      dynamic_cast<const RsaSsaPssParameters*>(parameters->get());
  ASSERT_THAT(rsa_ssa_pss_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pss_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(rsa_ssa_pss_parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(rsa_ssa_pss_parameters->GetSigHashType(),
              Eq(test_case.hash_type));
  EXPECT_THAT(rsa_ssa_pss_parameters->GetMgf1HashType(),
              Eq(test_case.hash_type));
  EXPECT_THAT(rsa_ssa_pss_parameters->GetSaltLengthInBytes(),
              Eq(test_case.salt_length_in_bytes));
  EXPECT_THAT(rsa_ssa_pss_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kRaw,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kUnknownPrefix,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersWithInvalidSigHashFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  {
    RsaSsaPssKeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);

    RsaSsaPssParams params;
    params.set_sig_hash(HashType::UNKNOWN_HASH);
    params.set_mgf1_hash(HashType::SHA256);
    params.set_salt_length(32);
    *key_format_proto.mutable_params() = params;

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);

    ASSERT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    RsaSsaPssKeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);

    RsaSsaPssParams params;
    params.set_sig_hash(static_cast<HashType>(6));
    params.set_mgf1_hash(HashType::SHA256);
    params.set_salt_length(32);
    *key_format_proto.mutable_params() = params;

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);

    ASSERT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersWithUnknownMgf1HashFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  {
    RsaSsaPssKeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);

    RsaSsaPssParams params;
    params.set_sig_hash(HashType::SHA256);
    params.set_mgf1_hash(HashType::UNKNOWN_HASH);
    params.set_salt_length(32);
    *key_format_proto.mutable_params() = params;

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);

    ASSERT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    RsaSsaPssKeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);

    RsaSsaPssParams params;
    params.set_sig_hash(HashType::SHA256);
    params.set_mgf1_hash(static_cast<HashType>(6));
    params.set_salt_length(32);
    *key_format_proto.mutable_params() = params;

    absl::StatusOr<internal::ProtoParametersSerialization> serialization =
        internal::ProtoParametersSerialization::Create(
            kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
            key_format_proto.SerializeAsString());
    ASSERT_THAT(serialization, IsOk());

    absl::StatusOr<std::unique_ptr<Parameters>> parameters =
        internal::MutableSerializationRegistry::GlobalInstance()
            .ParseParameters(*serialization);

    ASSERT_THAT(parameters.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParseParametersWithMismatchedHashTypesFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssKeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA512);
  params.set_salt_length(32);
  *key_format_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kPrivateTypeUrl, OutputPrefixTypeEnum::kTink,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);

  ASSERT_THAT(parameters.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPssProtoSerializationTest, SerializeParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(test_case.variant)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  const internal::ProtoKeyTemplate& key_template =
      proto_serialization->GetProtoKeyTemplate();
  EXPECT_THAT(key_template.type_url(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(key_template.output_prefix_type(),
              Eq(static_cast<internal::OutputPrefixTypeEnum>(
                  test_case.output_prefix_type)));

  RsaSsaPssKeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().sig_hash(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(key_format.params().mgf1_hash(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(key_format.params().salt_length(),
              Eq(test_case.salt_length_in_bytes));
  EXPECT_THAT(key_format.modulus_size_in_bits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(key_format.public_exponent(), Eq(kF4Str));
}

struct KeyValues {
  std::string n;
  std::string e;
  std::string p;
  std::string q;
  std::string dp;
  std::string dq;
  std::string d;
  std::string q_inv;
};

KeyValues GenerateKeyValues(int modulus_size_in_bits) {
  internal::SslUniquePtr<RSA> rsa(RSA_new());
  CHECK_NE(rsa.get(), nullptr);

  // Set public exponent to 65537.
  internal::SslUniquePtr<BIGNUM> e(BN_new());
  CHECK_NE(e.get(), nullptr);
  BN_set_word(e.get(), 65537);

  // Generate an RSA key pair and get the values.
  CHECK(RSA_generate_key_ex(rsa.get(), modulus_size_in_bits, e.get(),
                            /*cb=*/nullptr));

  const BIGNUM *n_bn, *e_bn, *d_bn, *p_bn, *q_bn, *dp_bn, *dq_bn, *q_inv_bn;

  RSA_get0_key(rsa.get(), &n_bn, &e_bn, &d_bn);

  absl::StatusOr<std::string> n_str =
      internal::BignumToString(n_bn, BN_num_bytes(n_bn));
  CHECK_OK(n_str);
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  CHECK_OK(e_str);
  absl::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  CHECK_OK(d_str);

  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);

  absl::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  CHECK_OK(p_str);
  absl::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  CHECK_OK(q_str);

  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  absl::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  CHECK_OK(dp_str);
  absl::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  CHECK_OK(dq_str);
  absl::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  CHECK_OK(q_inv_str);

  return KeyValues{*n_str,  *e_str,  *p_str, *q_str,
                   *dp_str, *dq_str, *d_str, *q_inv_str};
}

const KeyValues& Get2048BitKeyValues() {
  static absl::NoDestructor<KeyValues> values(GenerateKeyValues(2048));
  return *values;
}

TEST_P(RsaSsaPssProtoSerializationTest, ParsePublicKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(test_case.proto_hash_type);
  params.set_mgf1_hash(test_case.proto_hash_type);
  params.set_salt_length(test_case.salt_length_in_bytes);

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::RsaSsaPssPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<RsaSsaPssParameters> expected_parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(test_case.variant)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> expected_key =
      RsaSsaPssPublicKey::Create(*expected_parameters, BigInteger(key_values.n),
                                 test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest, ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPssPublicKey key_proto;
  key_proto.set_version(1);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPublicTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(RsaSsaPssProtoSerializationTest, SerializePublicKeySucceeds) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(test_case.variant)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> key =
      RsaSsaPssPublicKey::Create(*parameters, BigInteger(key_values.n),
                                 test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPublicTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());

  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPublicTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPublic));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::RsaSsaPssPublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().sig_hash(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(proto_key.params().mgf1_hash(), Eq(test_case.proto_hash_type));
  EXPECT_THAT(proto_key.params().salt_length(),
              Eq(test_case.salt_length_in_bytes));
}

TEST_P(RsaSsaPssProtoSerializationTest, ParsePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(test_case.proto_hash_type);
  params.set_mgf1_hash(test_case.proto_hash_type);
  params.set_salt_length(test_case.salt_length_in_bytes);

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, test_case.output_prefix_type,
          test_case.id);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key)->GetIdRequirement(), Eq(test_case.id));
  EXPECT_THAT((*key)->GetParameters().HasIdRequirement(),
              test_case.id.has_value());

  absl::StatusOr<RsaSsaPssParameters> expected_parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(test_case.variant)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> expected_public_key =
      RsaSsaPssPublicKey::Create(*expected_parameters, BigInteger(key_values.n),
                                 test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<RsaSsaPssPrivateKey> expected_private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*expected_public_key)
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());

  EXPECT_THAT(**key, Eq(*expected_private_key));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RestrictedData serialized_key =
      RestrictedData("invalid_serialization", InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest, ParsePrivateKeyWithNoPublicKeyFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(1);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 keys are accepted")));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(1);  // invalid version
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  EXPECT_THAT(key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Only version 0 public keys are accepted")));
}

TEST_F(RsaSsaPssProtoSerializationTest, ParsePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPssPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPssPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          kPrivateTypeUrl, serialized_key,
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/0x23456789);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, /*token=*/absl::nullopt);
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_P(RsaSsaPssProtoSerializationTest, SerializePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(test_case.variant)
          .SetSigHashType(test_case.hash_type)
          .SetMgf1HashType(test_case.hash_type)
          .SetSaltLengthInBytes(test_case.salt_length_in_bytes)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(*parameters, BigInteger(key_values.n),
                                 test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kPrivateTypeUrl));

  const internal::ProtoKeySerialization* proto_serialization =
      dynamic_cast<const internal::ProtoKeySerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->TypeUrl(), Eq(kPrivateTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyMaterialTypeEnum(),
              Eq(KeyMaterialTypeEnum::kAsymmetricPrivate));
  EXPECT_THAT(proto_serialization->GetOutputPrefixTypeEnum(),
              Eq(test_case.output_prefix_type));
  EXPECT_THAT(proto_serialization->IdRequirement(), Eq(test_case.id));

  google::crypto::tink::RsaSsaPssPrivateKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.p(), Eq(key_values.p));
  EXPECT_THAT(proto_key.q(), Eq(key_values.q));
  EXPECT_THAT(proto_key.dp(), Eq(key_values.dp));
  EXPECT_THAT(proto_key.dq(), Eq(key_values.dq));
  EXPECT_THAT(proto_key.d(), Eq(key_values.d));
  EXPECT_THAT(proto_key.crt(), Eq(key_values.q_inv));
  EXPECT_THAT(proto_key.has_public_key(), IsTrue());
  EXPECT_THAT(proto_key.public_key().version(), Eq(0));
  EXPECT_THAT(proto_key.public_key().n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.public_key().e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.public_key().has_params(), IsTrue());
  EXPECT_THAT(proto_key.public_key().params().sig_hash(),
              Eq(test_case.proto_hash_type));
  EXPECT_THAT(proto_key.public_key().params().mgf1_hash(),
              Eq(test_case.proto_hash_type));
  EXPECT_THAT(proto_key.public_key().params().salt_length(),
              Eq(test_case.salt_length_in_bytes));
}

TEST_F(RsaSsaPssProtoSerializationTest,
       SerializePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(key_values.n),
      /*id_requirement=*/0x23456789, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(key_values.p,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeQ(RestrictedBigInteger(key_values.q,
                                          InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentP(RestrictedBigInteger(
              key_values.dp, InsecureSecretKeyAccess::Get()))
          .SetPrimeExponentQ(RestrictedBigInteger(
              key_values.dq, InsecureSecretKeyAccess::Get()))
          .SetPrivateExponent(RestrictedBigInteger(
              key_values.d, InsecureSecretKeyAccess::Get()))
          .SetCrtCoefficient(RestrictedBigInteger(
              key_values.q_inv, InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

struct KeyAndSerialization {
  KeyAndSerialization(absl::string_view test_name, std::shared_ptr<Key> key,
                      ProtoKeySerialization proto_key_serialization)
      : test_name(test_name),
        key(std::move(key)),
        proto_key_serialization(std::move(proto_key_serialization)) {}

  std::string test_name;
  std::shared_ptr<Key> key;
  ProtoKeySerialization proto_key_serialization;
};

class SerializationTest : public testing::TestWithParam<KeyAndSerialization> {};
class ParseTest : public testing::TestWithParam<KeyAndSerialization> {};

TEST_P(SerializationTest, SerializesCorrectly) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<ProtoKeySerialization>(*test_key.key,
                                               InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization.status(), IsOk());
  ProtoKeySerialization* proto_serialization =
      dynamic_cast<ProtoKeySerialization*>(serialization->get());
  ASSERT_THAT(proto_serialization, Not(IsNull()));
  EXPECT_THAT(*proto_serialization,
              EqualsProtoKeySerialization(test_key.proto_key_serialization));
}

TEST_P(ParseTest, ParserCorrectly) {
  ASSERT_THAT(RegisterRsaSsaPssProtoSerialization(), IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          test_key.proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_TRUE(**key == *test_key.key);
}

KeyAndSerialization PublicKeyAndSerializationTink() {
  KeyValues values = Get2048BitKeyValues();
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(11)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(values.n), 101020, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(HashType::SHA256),
            FieldWithNumber(2).IsVarint(HashType::SHA256),
            FieldWithNumber(3).IsVarint(11)}),
       FieldWithNumber(3).IsString(values.n),
       FieldWithNumber(4).IsString(values.e)},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
      101020);

  return KeyAndSerialization("PublicKeyTink",
                             std::make_shared<RsaSsaPssPublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PublicKeyAndSerializationRaw() {
  KeyValues values = Get2048BitKeyValues();
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(0)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(values.n), absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(1).IsVarint(HashType::SHA512),
            FieldWithNumber(2).IsVarint(HashType::SHA512)}),
       FieldWithNumber(3).IsString(values.n),
       FieldWithNumber(4).IsString(values.e)},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

  return KeyAndSerialization("PublicKeyRAW",
                             std::make_shared<RsaSsaPssPublicKey>(*public_key),
                             serialization);
}

KeyAndSerialization PrivateKeyAndSerializationRaw() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(77)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(values.n), absl::nullopt, GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(values.p, token))
          .SetPrimeQ(RestrictedBigInteger(values.q, token))
          .SetPrimeExponentP(RestrictedBigInteger(values.dp, token))
          .SetPrimeExponentQ(RestrictedBigInteger(values.dq, token))
          .SetPrivateExponent(RestrictedBigInteger(values.d, token))
          .SetCrtCoefficient(RestrictedBigInteger(values.q_inv, token))
          .Build(GetPartialKeyAccess());

  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(HashType::SHA512),
                 FieldWithNumber(2).IsVarint(HashType::SHA512),
                 FieldWithNumber(3).IsVarint(77)}),
            FieldWithNumber(3).IsString(values.n),
            FieldWithNumber(4).IsString(values.e)}),
       FieldWithNumber(3).IsString(values.d),
       FieldWithNumber(4).IsString(values.p),
       FieldWithNumber(5).IsString(values.q),
       FieldWithNumber(6).IsString(values.dp),
       FieldWithNumber(7).IsString(values.dq),
       FieldWithNumber(8).IsString(values.q_inv)},
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

  return KeyAndSerialization(
      "PrivateKeyRAW", std::make_shared<RsaSsaPssPrivateKey>(*private_key),
      serialization);
}

KeyAndSerialization PrivateKeyAndSerializationTink() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSaltLengthInBytes(0)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(values.n), 4455, GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(values.p, token))
          .SetPrimeQ(RestrictedBigInteger(values.q, token))
          .SetPrimeExponentP(RestrictedBigInteger(values.dp, token))
          .SetPrimeExponentQ(RestrictedBigInteger(values.dq, token))
          .SetPrivateExponent(RestrictedBigInteger(values.d, token))
          .SetCrtCoefficient(RestrictedBigInteger(values.q_inv, token))
          .Build(GetPartialKeyAccess());

  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(HashType::SHA512),
                 FieldWithNumber(2).IsVarint(HashType::SHA512)}),
            FieldWithNumber(3).IsString(values.n),
            FieldWithNumber(4).IsString(values.e)}),
       FieldWithNumber(3).IsString(values.d),
       FieldWithNumber(4).IsString(values.p),
       FieldWithNumber(5).IsString(values.q),
       FieldWithNumber(6).IsString(values.dp),
       FieldWithNumber(7).IsString(values.dq),
       FieldWithNumber(8).IsString(values.q_inv)},
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
      4455);

  return KeyAndSerialization(
      "PrivateKeyTINK", std::make_shared<RsaSsaPssPrivateKey>(*private_key),
      serialization);
}

KeyAndSerialization PrivateKeyAndSerializationNonCanonical() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSaltLengthInBytes(0)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPssPublicKey> public_key = RsaSsaPssPublicKey::Create(
      *parameters, BigInteger(values.n), 4455, GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPssPrivateKey> private_key =
      RsaSsaPssPrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetPrimeP(RestrictedBigInteger(values.p, token))
          .SetPrimeQ(RestrictedBigInteger(values.q, token))
          .SetPrimeExponentP(RestrictedBigInteger(values.dp, token))
          .SetPrimeExponentQ(RestrictedBigInteger(values.dq, token))
          .SetPrivateExponent(RestrictedBigInteger(values.d, token))
          .SetCrtCoefficient(RestrictedBigInteger(values.q_inv, token))
          .Build(GetPartialKeyAccess());

  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
      {FieldWithNumber(1).IsVarint(1000),  // Bad version
       FieldWithNumber(1).IsVarint(0),     // Overwrite bad version number
       FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage({
                FieldWithNumber(2).IsVarint(HashType::SHA512),
                FieldWithNumber(1).IsVarint(HashType::SHA512),  // Not ordered
                FieldWithNumber(3).IsVarint(0),  // Salt length explicit
            }),
            FieldWithNumber(3).IsString(values.n),
            FieldWithNumber(4).IsString(values.e)}),
       FieldWithNumber(4).IsString(values.p),  // Not ordered
       FieldWithNumber(5).IsString(values.q),
       FieldWithNumber(6).IsString(values.dp),
       FieldWithNumber(7).IsString(values.dq),
       FieldWithNumber(3).IsString(values.d),
       FieldWithNumber(8).IsString(values.q_inv)},
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
      4455);

  return KeyAndSerialization(
      "PrivateKeyTinkNonCanonical",
      std::make_shared<RsaSsaPssPrivateKey>(*private_key), serialization);
}

INSTANTIATE_TEST_SUITE_P(
    SerializationTest, SerializationTest,
    testing::Values(PublicKeyAndSerializationTink(),
                    PublicKeyAndSerializationRaw(),
                    PrivateKeyAndSerializationRaw(),
                    PrivateKeyAndSerializationTink()),
    [](testing::TestParamInfo<class KeyAndSerialization> info) {
      return info.param.test_name;
    });

INSTANTIATE_TEST_SUITE_P(
    ParseTest, ParseTest,
    testing::Values(PublicKeyAndSerializationTink(),
                    PublicKeyAndSerializationRaw(),
                    PrivateKeyAndSerializationRaw(),
                    PrivateKeyAndSerializationTink(),
                    PrivateKeyAndSerializationNonCanonical()),
    [](testing::TestParamInfo<class KeyAndSerialization> info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace tink
}  // namespace crypto
