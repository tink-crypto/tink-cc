// Copyright 2017 Google Inc.
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

#include "tink/signature/signature_config.h"

#include <list>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/absl_check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/config/global_registry.h"
#include "tink/crypto_format.h"
#include "tink/ec_point.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key_status.h"
#include "tink/keyset_handle_builder.h"
#include "tink/primitive_set.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/key_gen_config_v0.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "proto/rsa_ssa_pss.pb.h"
#ifdef OPENSSL_IS_BORINGSSL
#include "openssl/base.h"
#endif
#include "openssl/bn.h"
#include "openssl/rsa.h"
#include "tink/big_integer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/key.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/signature/ed25519_private_key.h"
#include "tink/signature/ed25519_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_private_key.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_private_key.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::internal::KeyMaterialTypeEnum;
using ::crypto::tink::internal::OutputPrefixTypeEnum;
using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::DummyPublicKeyVerify;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HashType;
using ::testing::HasSubstr;
using ::testing::Not;

class SignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  };
};

TEST_F(SignatureConfigTest, testBasic) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(SignatureConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeySign>(
                  RsaSsaPssSignKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<PublicKeyVerify>(
                  RsaSsaPssVerifyKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the PublicKeySignWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeySignWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeySign>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeySign>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  auto signature_result = wrapped.value()->Sign("message");
  ASSERT_TRUE(signature_result.ok());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  EXPECT_EQ(signature_result.value(),
            absl::StrCat(prefix,
                         DummyPublicKeySign("dummy").Sign("message").value()));
}

// Tests that the PublicKeyVerifyWrapper has been properly registered and we
// can wrap primitives.
TEST_F(SignatureConfigTest, PublicKeyVerifyWrapperRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  ASSERT_TRUE(SignatureConfig::Register().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<PublicKeyVerify>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyPublicKeyVerify>("dummy"),
                             key_info)
              .value()),
      IsOk());
  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  std::string signature = DummyPublicKeySign("dummy").Sign("message").value();

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_TRUE(wrapped.ok()) << wrapped.status();
  ASSERT_TRUE(
      wrapped.value()->Verify(absl::StrCat(prefix, signature), "message").ok());
}

// FIPS-only mode tests
TEST_F(SignatureConfigTest, RegisterNonFipsTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> non_fips_key_templates;
  non_fips_key_templates.push_back(SignatureKeyTemplates::Ed25519());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::Ed25519WithRawOutput());
  // 4096-bit RSA is not validated.
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha384Sha384F4());
  non_fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss4096Sha512Sha512F4());

  for (auto key_template : non_fips_key_templates) {
    EXPECT_THAT(
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry())
            .status(),
        Not(IsOk()));
  }
}

TEST_F(SignatureConfigTest, RegisterFipsValidTemplates) {
  if (!internal::IsFipsModeEnabled() || !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode with BoringCrypto.";
  }

  EXPECT_THAT(SignatureConfig::Register(), IsOk());

  std::list<google::crypto::tink::KeyTemplate> fips_key_templates;
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP256Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha384());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Sha512());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP384Ieee());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521());
  fips_key_templates.push_back(SignatureKeyTemplates::EcdsaP521Ieee());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4());
  fips_key_templates.push_back(
      SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4());

  for (auto key_template : fips_key_templates) {
    EXPECT_THAT(
        KeysetHandle::GenerateNew(key_template, KeyGenConfigGlobalRegistry()),
        IsOk());
  }
}

TEST_F(SignatureConfigTest, RsaSsaPkcs1ProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPkcs1Parameters> params =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(3072)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

struct RsaKeyValues {
  std::string n;
  std::string e;
  std::string p;
  std::string q;
  std::string dp;
  std::string dq;
  std::string d;
  std::string q_inv;
};

// Creates the values corresponding to an RSA key using OpenSSL.
RsaKeyValues GenerateRsaKeyValues(int modulus_size_in_bits) {
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
  ABSL_CHECK_OK(n_str);
  absl::StatusOr<std::string> e_str =
      internal::BignumToString(e_bn, BN_num_bytes(e_bn));
  ABSL_CHECK_OK(e_str);
  absl::StatusOr<std::string> d_str =
      internal::BignumToString(d_bn, BN_num_bytes(d_bn));
  ABSL_CHECK_OK(d_str);

  RSA_get0_factors(rsa.get(), &p_bn, &q_bn);

  absl::StatusOr<std::string> p_str =
      internal::BignumToString(p_bn, BN_num_bytes(p_bn));
  ABSL_CHECK_OK(p_str);
  absl::StatusOr<std::string> q_str =
      internal::BignumToString(q_bn, BN_num_bytes(q_bn));
  ABSL_CHECK_OK(q_str);

  RSA_get0_crt_params(rsa.get(), &dp_bn, &dq_bn, &q_inv_bn);

  absl::StatusOr<std::string> dp_str =
      internal::BignumToString(dp_bn, BN_num_bytes(dp_bn));
  ABSL_CHECK_OK(dp_str);
  absl::StatusOr<std::string> dq_str =
      internal::BignumToString(dq_bn, BN_num_bytes(dq_bn));
  ABSL_CHECK_OK(dq_str);
  absl::StatusOr<std::string> q_inv_str =
      internal::BignumToString(q_inv_bn, BN_num_bytes(q_inv_bn));
  ABSL_CHECK_OK(q_inv_str);

  return RsaKeyValues{*n_str,  *e_str,  *p_str, *q_str,
                      *dp_str, *dq_str, *d_str, *q_inv_str};
}

TEST_F(SignatureConfigTest, RsaSsaPkcs1ProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  RsaKeyValues key_values = GenerateRsaKeyValues(/*modulus_size_in_bits=*/2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  key_proto.mutable_params()->set_hash_type(HashType::SHA256);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPkcs1Parameters> params =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> key = RsaSsaPkcs1PublicKey::Create(
      *params, BigInteger(key_values.n),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, RsaSsaPkcs1ProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  RsaKeyValues key_values = GenerateRsaKeyValues(/*modulus_size_in_bits=*/2048);

  google::crypto::tink::RsaSsaPkcs1PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_n(key_values.n);
  public_key_proto.set_e(key_values.e);
  public_key_proto.mutable_params()->set_hash_type(HashType::SHA256);

  google::crypto::tink::RsaSsaPkcs1PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_p(key_values.p);
  private_key_proto.set_q(key_values.q);
  private_key_proto.set_dp(key_values.dp);
  private_key_proto.set_dq(key_values.dq);
  private_key_proto.set_d(key_values.d);
  private_key_proto.set_crt(key_values.q_inv);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPkcs1Parameters> params =
      RsaSsaPkcs1Parameters::Builder()
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kTink)
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<RsaSsaPkcs1PublicKey> public_key =
      RsaSsaPkcs1PublicKey::Create(*params, BigInteger(key_values.n),
                                   /*id_requirement=*/123,
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

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, RsaSsaPssProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              SignatureKeyTemplates::RsaSsaPss3072Sha256Sha256F4());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPssParameters> params =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(3072)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(SignatureConfigTest, RsaSsaPssProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  RsaKeyValues key_values = GenerateRsaKeyValues(/*modulus_size_in_bits=*/2048);

  google::crypto::tink::RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

  google::crypto::tink::RsaSsaPssPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_n(key_values.n);
  key_proto.set_e(key_values.e);
  *key_proto.mutable_params() = params;

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> key =
      RsaSsaPssPublicKey::Create(*parameters, BigInteger(key_values.n),
                                 /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, RsaSsaPssProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Not supported if FIPS-mode is used and BoringCrypto is "
                    "not available";
  }

  RsaKeyValues key_values = GenerateRsaKeyValues(/*modulus_size_in_bits=*/2048);

  google::crypto::tink::RsaSsaPssParams params;
  params.set_sig_hash(HashType::SHA256);
  params.set_mgf1_hash(HashType::SHA256);
  params.set_salt_length(32);

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

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<RsaSsaPssParameters> parameters =
      RsaSsaPssParameters::Builder()
          .SetVariant(RsaSsaPssParameters::Variant::kTink)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(2048)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<RsaSsaPssPublicKey> public_key =
      RsaSsaPssPublicKey::Create(*parameters, BigInteger(key_values.n),
                                 /*id_requirement=*/123, GetPartialKeyAccess());
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

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, EcdsaProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test non FIPS-mode only";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              SignatureKeyTemplates::EcdsaP256());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<EcdsaParameters> params =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(SignatureConfigTest, EcdsaProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test non FIPS-mode only";
  }

  google::crypto::tink::EcdsaParams params;
  params.set_curve(google::crypto::tink::EllipticCurveType::NIST_P256);
  params.set_hash_type(google::crypto::tink::HashType::SHA256);
  params.set_encoding(google::crypto::tink::EcdsaSignatureEncoding::DER);

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_x(ec_key->pub_x);
  key_proto.set_y(ec_key->pub_y);
  *key_proto.mutable_params() = params;
  RestrictedData serialized_key = RestrictedData(
      key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
          serialized_key, KeyMaterialTypeEnum::kAsymmetricPublic,
          OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  ASSERT_THAT(ec_key, IsOk());
  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *public_key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(KeyGenConfigGlobalRegistry())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *public_key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(KeyGenConfigGlobalRegistry())
                  .status(),
              IsOk());
}

TEST_F(SignatureConfigTest, EcdsaProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Test non FIPS-mode only";
  }

  google::crypto::tink::EcdsaParams params;
  params.set_curve(google::crypto::tink::EllipticCurveType::NIST_P256);
  params.set_hash_type(google::crypto::tink::HashType::SHA256);
  params.set_encoding(google::crypto::tink::EcdsaSignatureEncoding::DER);

  absl::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::EcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);
  *public_key_proto.mutable_params() = params;

  google::crypto::tink::EcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  RestrictedData serialized_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
          serialized_key, KeyMaterialTypeEnum::kAsymmetricPrivate,
          OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<EcdsaParameters> parameters =
      EcdsaParameters::Builder()
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetVariant(EcdsaParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  ASSERT_THAT(ec_key, IsOk());
  EcPoint public_point(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  RestrictedBigInteger private_key_value =
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get());

  absl::StatusOr<EcdsaPublicKey> public_key =
      EcdsaPublicKey::Create(*parameters, public_point,
                             /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<EcdsaPrivateKey> private_key = EcdsaPrivateKey::Create(
      *public_key, private_key_value, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  // Fails to serialize this key type.
  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *private_key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build()
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to serialize")));

  // Register serialization.
  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  EXPECT_THAT(KeysetHandleBuilder()
                  .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
                      *private_key, KeyStatus::kEnabled, /*is_primary=*/true))
                  .Build(),
              IsOk());
}

TEST_F(SignatureConfigTest, Ed25519ProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              SignatureKeyTemplates::Ed25519());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

TEST_F(SignatureConfigTest, Ed25519ProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const std::string raw_key = subtle::Random::GetRandomBytes(32);

  google::crypto::tink::Ed25519PublicKey key_proto;
  key_proto.set_version(0);
  key_proto.set_key_value(raw_key);

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
          RestrictedData(key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPublic, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<Ed25519PublicKey> key =
      Ed25519PublicKey::Create(*params, raw_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(SignatureConfigTest, Ed25519ProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<std::unique_ptr<internal::Ed25519Key>> key_pair =
      internal::NewEd25519Key();
  ASSERT_THAT(key_pair, IsOk());

  google::crypto::tink::Ed25519PublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_key_value((*key_pair)->public_key);

  google::crypto::tink::Ed25519PrivateKey private_key_proto;
  private_key_proto.set_version(0);
  private_key_proto.set_key_value(
      util::SecretDataAsStringView((*key_pair)->private_key));
  *private_key_proto.mutable_public_key() = public_key_proto;

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyMaterialTypeEnum::kAsymmetricPrivate, OutputPrefixTypeEnum::kTink,
          /*id_requirement=*/123);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Ed25519Parameters> params =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<Ed25519PublicKey> public_key =
      Ed25519PublicKey::Create(*params, (*key_pair)->public_key,
                               /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData private_key_bytes =
      RestrictedData((*key_pair)->private_key, InsecureSecretKeyAccess::Get());

  absl::StatusOr<Ed25519PrivateKey> private_key = Ed25519PrivateKey::Create(
      *public_key, private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(SignatureConfig::Register(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key2, IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
