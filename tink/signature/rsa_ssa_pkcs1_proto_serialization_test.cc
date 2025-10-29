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
#include "tink/signature/rsa_ssa_pkcs1_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/util/test_util.h"
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
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/util/test_matchers.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::internal::ProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::EqualsProtoKeySerialization;
using ::crypto::tink::internal::proto_testing::FieldWithNumber;
using ::crypto::tink::internal::proto_testing::SerializeMessage;
using ::crypto::tink::test::HexDecodeOrDie;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;

using ::google::crypto::tink::RsaSsaPkcs1KeyFormat;
using ::google::crypto::tink::RsaSsaPkcs1Params;
using ::testing::Eq;
using ::testing::IsNull;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  RsaSsaPkcs1Parameters::Variant variant;
  OutputPrefixTypeEnum output_prefix_type;
  RsaSsaPkcs1Parameters::HashType hash_type;
  HashType proto_hash_type;
  int modulus_size_in_bits;
  absl::optional<int> id;
  std::string output_prefix;
};

const std::string& kF4Str = *new std::string("\x1\0\x1", 3);  // 65537

const absl::string_view kPrivateTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
const absl::string_view kPublicTypeUrl =
    "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";

class RsaSsaPkcs1ProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(RsaSsaPkcs1ProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    RsaSsaPkcs1ProtoSerializationTestSuite, RsaSsaPkcs1ProtoSerializationTest,
    Values(TestCase{RsaSsaPkcs1Parameters::Variant::kTink,
                    OutputPrefixTypeEnum::kTink,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x02030400,
                    /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kCrunchy,
                    OutputPrefixTypeEnum::kCrunchy,
                    RsaSsaPkcs1Parameters::HashType::kSha256, HashType::SHA256,
                    /*modulus_size=*/2048, /*id=*/0x01030005,
                    /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kLegacy,
                    OutputPrefixTypeEnum::kLegacy,
                    RsaSsaPkcs1Parameters::HashType::kSha384, HashType::SHA384,
                    /*modulus_size=*/3072, /*id=*/0x07080910,
                    /*output_prefix=*/std::string("\x00\x07\x08\x09\x10", 5)},
           TestCase{RsaSsaPkcs1Parameters::Variant::kNoPrefix,
                    OutputPrefixTypeEnum::kRaw,
                    RsaSsaPkcs1Parameters::HashType::kSha512, HashType::SHA512,
                    /*modulus_size=*/3072, /*id=*/absl::nullopt,
                    /*output_prefix=*/""}));

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParseParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(test_case.modulus_size_in_bits);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(test_case.proto_hash_type);

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
  const RsaSsaPkcs1Parameters* rsa_ssa_pkcs1_parameters =
      dynamic_cast<const RsaSsaPkcs1Parameters*>(parameters->get());
  ASSERT_THAT(rsa_ssa_pkcs1_parameters, NotNull());
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetModulusSizeInBits(),
              Eq(test_case.modulus_size_in_bits));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetHashType(), Eq(test_case.hash_type));
  EXPECT_THAT(rsa_ssa_pkcs1_parameters->GetPublicExponent(),
              Eq(BigInteger(kF4Str)));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersKeyFormatWithoutParamsFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1KeyFormat key_format_proto;
  key_format_proto.set_modulus_size_in_bits(2048);
  key_format_proto.set_public_exponent(kF4Str);
  key_format_proto.mutable_params()->set_hash_type(HashType::SHA256);

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

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParseParametersWithInvalidHashFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  {
    // Unknown hash.
    RsaSsaPkcs1KeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);
    key_format_proto.mutable_params()->set_hash_type(HashType::UNKNOWN_HASH);

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
    // Out of range hash.
    RsaSsaPkcs1KeyFormat key_format_proto;
    key_format_proto.set_modulus_size_in_bits(2048);
    key_format_proto.set_public_exponent(kF4Str);
    key_format_proto.mutable_params()->set_hash_type(static_cast<HashType>(6));

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

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializeParametersSucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(kF4Str))
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
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_THAT(key_format.ParseFromString(key_template.value()), IsTrue());

  ASSERT_THAT(key_format.has_params(), IsTrue());
  EXPECT_THAT(key_format.params().hash_type(), Eq(test_case.proto_hash_type));
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

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParsePublicKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(test_case.proto_hash_type);

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::RsaSsaPkcs1PublicKey key_proto;
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

  absl::StatusOr<RsaSsaPkcs1Parameters> expected_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> expected_key =
      RsaSsaPkcs1PublicKey::Create(*expected_parameters,
                                   BigInteger(key_values.n), test_case.id,
                                   GetPartialKeyAccess());
  ASSERT_THAT(expected_key, IsOk());

  EXPECT_THAT(**key, Eq(*expected_key));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePublicKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(HashType::SHA256);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey key_proto;
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

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializePublicKeySucceeds) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  TestCase test_case = GetParam();
  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(key_values.n),
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

  google::crypto::tink::RsaSsaPkcs1PublicKey proto_key;
  ASSERT_THAT(proto_key.ParseFromString(
                  proto_serialization->SerializedKeyProto().GetSecret(
                      InsecureSecretKeyAccess::Get())),
              IsTrue());

  EXPECT_THAT(proto_key.version(), Eq(0));
  EXPECT_THAT(proto_key.n(), Eq(key_values.n));
  EXPECT_THAT(proto_key.e(), Eq(key_values.e));
  EXPECT_THAT(proto_key.has_params(), IsTrue());
  EXPECT_THAT(proto_key.params().hash_type(), Eq(test_case.proto_hash_type));
}

TEST_P(RsaSsaPkcs1ProtoSerializationTest, ParsePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(test_case.proto_hash_type);

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  google::crypto::tink::RsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
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

  absl::StatusOr<RsaSsaPkcs1Parameters> expected_parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> expected_public_key =
      RsaSsaPkcs1PublicKey::Create(*expected_parameters,
                                   BigInteger(key_values.n), test_case.id,
                                   GetPartialKeyAccess());
  ASSERT_THAT(expected_public_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> expected_private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

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

TEST_F(RsaSsaPkcs1ProtoSerializationTest, ParsePrivateKeyWithNoPublicKeyFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
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

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(HashType::SHA256);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyWithInvalidPublicKeyVersionFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(HashType::SHA256);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(1);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
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
  EXPECT_THAT(key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       ParsePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  RsaSsaPkcs1Params params;
  params.set_hash_type(HashType::SHA256);

  KeyValues key_values = GenerateKeyValues(2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
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

TEST_P(RsaSsaPkcs1ProtoSerializationTest, SerializePrivateKeySucceeds) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(test_case.modulus_size_in_bits);

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(test_case.variant)
          .SetHashType(test_case.hash_type)
          .SetModulusSizeInBits(test_case.modulus_size_in_bits)
          .SetPublicExponent(BigInteger(key_values.e))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(key_values.n),
                                   test_case.id, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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

  google::crypto::tink::RsaSsaPkcs1PrivateKey proto_key;
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
  EXPECT_THAT(proto_key.public_key().params().hash_type(),
              Eq(test_case.proto_hash_type));
}

TEST_F(RsaSsaPkcs1ProtoSerializationTest,
       SerializePrivateKeyNoSecretKeyAccessFails) {
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());

  KeyValues key_values = GenerateKeyValues(2048);

  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(2048)
          .SetPublicExponent(BigInteger(kF4Str))
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(key_values.n),
                                   /*id_requirement=*/0x23456789,
                                   GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
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
  ASSERT_THAT(RegisterRsaSsaPkcs1ProtoSerialization(), IsOk());
  const KeyAndSerialization& test_key = GetParam();

  absl::StatusOr<std::unique_ptr<Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          test_key.proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key.status(), IsOk());
  EXPECT_TRUE(**key == *test_key.key);
}

KeyAndSerialization PublicKeyAndSerializationTink() {
  KeyValues values = Get2048BitKeyValues();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n), 101020,
                                   GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
      {FieldWithNumber(2).IsSubMessage({
           FieldWithNumber(1).IsVarint(HashType::SHA256),
       }),
       FieldWithNumber(3).IsString(values.n),
       FieldWithNumber(4).IsString(values.e)},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
      101020);

  return KeyAndSerialization(
      "PublicKeyTink", std::make_shared<RsaSsaPkcs1PublicKey>(*public_key),
      serialization);
}

KeyAndSerialization PublicKeyAndSerializationRaw() {
  KeyValues values = Get2048BitKeyValues();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n),
                                   absl::nullopt, GetPartialKeyAccess());
  CHECK_OK(public_key.status());
  ProtoKeySerialization serialization = SerializeMessage(
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
      {FieldWithNumber(2).IsSubMessage({
           FieldWithNumber(1).IsVarint(HashType::SHA512),
       }),
       FieldWithNumber(3).IsString(values.n),
       FieldWithNumber(4).IsString(values.e)},
      KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kRaw,
      absl::nullopt);

  return KeyAndSerialization(
      "PublicKeyRAW", std::make_shared<RsaSsaPkcs1PublicKey>(*public_key),
      serialization);
}

KeyAndSerialization PrivateKeyAndSerializationRaw() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n),
                                   absl::nullopt, GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage({
                FieldWithNumber(1).IsVarint(HashType::SHA512),
            }),
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
      "PrivateKeyRAW", std::make_shared<RsaSsaPkcs1PrivateKey>(*private_key),
      serialization);
}

KeyAndSerialization PrivateKeyAndSerializationTink() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n), 4455,
                                   GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(HashType::SHA512)}),
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
      "PrivateKeyTINK", std::make_shared<RsaSsaPkcs1PrivateKey>(*private_key),
      serialization);
}

KeyAndSerialization PrivateKeyAndSerializationNonCanonical() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n), 4455,
                                   GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      {FieldWithNumber(1).IsVarint(1000),  // Bad version
       FieldWithNumber(1).IsVarint(0),     // Overwrite bad version number
       FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage(
                {FieldWithNumber(1).IsVarint(HashType::SHA512)}),
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
      std::make_shared<RsaSsaPkcs1PrivateKey>(*private_key), serialization);
}

// Padded big ints.
KeyAndSerialization PrivateKeyAndSerializationNonCanonical2() {
  KeyValues values = Get2048BitKeyValues();
  SecretKeyAccessToken token = InsecureSecretKeyAccess::Get();
  std::string zero = HexDecodeOrDie("00");
  absl::StatusOr<RsaSsaPkcs1Parameters> parameters =
      RsaSsaPkcs1Parameters::Builder()
          .SetModulusSizeInBits(2048)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .Build();
  CHECK_OK(parameters.status());
  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*parameters, BigInteger(values.n), 4455,
                                   GetPartialKeyAccess());
  absl::StatusOr<RsaSsaPkcs1PrivateKey> private_key =
      RsaSsaPkcs1PrivateKey::Builder()
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
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
      {FieldWithNumber(2).IsSubMessage(
           {FieldWithNumber(2).IsSubMessage({
                FieldWithNumber(1).IsVarint(
                    HashType::SHA512)  // Salt length explicit
            }),
            FieldWithNumber(3).IsString(absl::StrCat(zero, values.n)),
            FieldWithNumber(4).IsString(absl::StrCat(zero, values.e))}),
       FieldWithNumber(3).IsString(absl::StrCat(zero, values.d)),
       FieldWithNumber(4).IsString(absl::StrCat(zero, values.p)),
       FieldWithNumber(5).IsString(absl::StrCat(zero, values.q)),
       FieldWithNumber(6).IsString(absl::StrCat(zero, values.dp)),
       FieldWithNumber(7).IsString(absl::StrCat(zero, values.dq)),
       FieldWithNumber(8).IsString(absl::StrCat(zero, values.q_inv))},
      KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
      4455);

  return KeyAndSerialization(
      "PrivateKeyTinkNonCanonical2",
      std::make_shared<RsaSsaPkcs1PrivateKey>(*private_key), serialization);
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
                    PrivateKeyAndSerializationNonCanonical(),
                    PrivateKeyAndSerializationNonCanonical2()),
    [](testing::TestParamInfo<class KeyAndSerialization> info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace tink
}  // namespace crypto
