// Copyright 2023 Google Inc.
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

#include "tink/jwt/jwt_signature_config.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/big_integer.h"
#include "tink/config/global_registry.h"
#include "tink/ec_point.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/jwt/jwt_ecdsa_parameters.h"
#include "tink/jwt/jwt_ecdsa_private_key.h"
#include "tink/jwt/jwt_ecdsa_public_key.h"
#include "tink/jwt/jwt_key_templates.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/registry.h"
#include "tink/restricted_big_integer.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/jwt_ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::JwtEcdsaAlgorithm;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Not;

class JwtSignatureConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(JwtSignatureConfigTest, FailIfAndOnlyIfInInvalidFipsState) {
  // If FIPS is enabled, then we need FIPS also to be enabled in BoringSSL.
  // Otherwise we are in an invalid state and must fail.
  bool invalid_fips_state =
      internal::IsFipsModeEnabled() && !internal::IsFipsEnabledInSsl();

  if (invalid_fips_state) {
    EXPECT_THAT(JwtSignatureRegister(), Not(IsOk()));

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                Not(IsOk()));
  } else {
    EXPECT_THAT(JwtSignatureRegister(), IsOk());

    EXPECT_THAT(KeysetHandle::GenerateNew(JwtEs256Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtRs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(JwtPs256_2048_F4_Template(),
                                          KeyGenConfigGlobalRegistry())
                    .status(),
                IsOk());
  }
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoParamsSerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(JwtEs256Template());
  ASSERT_THAT(proto_params_serialization, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*proto_params_serialization)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters)
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization),
      IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeParameters<internal::ProtoParametersSerialization>(
                      *parameters),
              IsOk());
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoPublicKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",
          RestrictedData(public_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PUBLIC, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *public_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

TEST_F(JwtSignatureConfigTest, JwtEcdsaProtoPrivateKeySerializationRegistered) {
  if (internal::IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  util::StatusOr<internal::EcKey> ec_key =
      internal::NewEcKey(subtle::EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key, IsOk());

  google::crypto::tink::JwtEcdsaPublicKey public_key_proto;
  public_key_proto.set_version(0);
  public_key_proto.set_algorithm(JwtEcdsaAlgorithm::ES256);
  public_key_proto.set_x(ec_key->pub_x);
  public_key_proto.set_y(ec_key->pub_y);

  google::crypto::tink::JwtEcdsaPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_key_value(util::SecretDataAsStringView(ec_key->priv));

  util::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          KeyData::ASYMMETRIC_PRIVATE, OutputPrefixType::RAW,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  ASSERT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKey(*proto_key_serialization, InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));

  util::StatusOr<JwtEcdsaParameters> parameters =
      JwtEcdsaParameters::Create(JwtEcdsaParameters::KidStrategy::kIgnored,
                                 JwtEcdsaParameters::Algorithm::kEs256);
  ASSERT_THAT(parameters, IsOk());

  EcPoint public_point =
      EcPoint(BigInteger(ec_key->pub_x), BigInteger(ec_key->pub_y));
  util::StatusOr<JwtEcdsaPublicKey> public_key =
      JwtEcdsaPublicKey::Builder()
          .SetParameters(*parameters)
          .SetPublicPoint(public_point)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  util::StatusOr<JwtEcdsaPrivateKey> private_key = JwtEcdsaPrivateKey::Create(
      *public_key,
      RestrictedBigInteger(util::SecretDataAsStringView(ec_key->priv),
                           InsecureSecretKeyAccess::Get()),
      GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  ASSERT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(JwtSignatureRegister(), IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
                  *proto_key_serialization, InsecureSecretKeyAccess::Get()),
              IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .SerializeKey<internal::ProtoKeySerialization>(
                      *private_key, InsecureSecretKeyAccess::Get()),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
