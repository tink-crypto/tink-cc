// Copyright 2017 Google LLC
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

#include "tink/signature/ecdsa_verify_key_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_verify.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_private_key.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/internal/testing/ecdsa_test_vectors.h"
#include "tink/signature/internal/testing/signature_test_vector.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::crypto::tink::util::Enums;
using ::google::crypto::tink::EcdsaParams;
using EcdsaPrivateKeyProto = ::google::crypto::tink::EcdsaPrivateKey;
using EcdsaPublicKeyProto = ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::Not;

namespace {

TEST(EcdsaVerifyKeyManagerTest, Basics) {
  EXPECT_THAT(EcdsaVerifyKeyManager().get_version(), Eq(0));
  EXPECT_THAT(EcdsaVerifyKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PUBLIC));
  EXPECT_THAT(EcdsaVerifyKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.EcdsaPublicKey"));
}

TEST(EcdsaVerifyKeyManagerTest, ValidateEmptyKey) {
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(EcdsaPublicKeyProto()),
              Not(IsOk()));
}

HashType ToProtoHashType(EcdsaParameters::HashType hash_type) {
  switch (hash_type) {
    case EcdsaParameters::HashType::kSha256:
      return HashType::SHA256;
    case EcdsaParameters::HashType::kSha384:
      return HashType::SHA384;
    case EcdsaParameters::HashType::kSha512:
      return HashType::SHA512;
    default:
      return HashType::UNKNOWN_HASH;
  }
}

EllipticCurveType ToProtoCurveType(EcdsaParameters::CurveType curve_type) {
  switch (curve_type) {
    case EcdsaParameters::CurveType::kNistP256:
      return EllipticCurveType::NIST_P256;
    case EcdsaParameters::CurveType::kNistP384:
      return EllipticCurveType::NIST_P384;
    case EcdsaParameters::CurveType::kNistP521:
      return EllipticCurveType::NIST_P521;
    default:
      return EllipticCurveType::UNKNOWN_CURVE;
  }
}

EcdsaSignatureEncoding ToProtoSignatureEncoding(
    EcdsaParameters::SignatureEncoding encoding) {
  switch (encoding) {
    case EcdsaParameters::SignatureEncoding::kDer:
      return EcdsaSignatureEncoding::DER;
    case EcdsaParameters::SignatureEncoding::kIeeeP1363:
      return EcdsaSignatureEncoding::IEEE_P1363;
    default:
      return EcdsaSignatureEncoding::UNKNOWN_ENCODING;
  }
}

EcdsaPublicKeyProto ToEcdsaPublicKeyProto(const EcdsaPublicKey& public_key) {
  EcdsaPublicKeyProto proto;
  proto.set_version(0);
  proto.set_x(std::string(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetX().GetValue()));
  proto.set_y(std::string(
      public_key.GetPublicPoint(GetPartialKeyAccess()).GetY().GetValue()));
  EcdsaParams* params = proto.mutable_params();
  params->set_hash_type(
      ToProtoHashType(public_key.GetParameters().GetHashType()));
  params->set_curve(
      ToProtoCurveType(public_key.GetParameters().GetCurveType()));
  params->set_encoding(ToProtoSignatureEncoding(
      public_key.GetParameters().GetSignatureEncoding()));
  return proto;
}

EcdsaPublicKeyProto CreateValidPublicKey() {
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(EcdsaParameters::CurveType::kNistP256,
                                   EcdsaParameters::HashType::kSha256,
                                   EcdsaParameters::SignatureEncoding::kDer,
                                   EcdsaParameters::Variant::kNoPrefix);
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  return ToEcdsaPublicKeyProto(private_key.GetPublicKey());
}

EcdsaPrivateKeyProto CreateValidPrivateKey() {
  const internal::SignatureTestVector& test_vector =
      internal::GetEcdsaTestVector(EcdsaParameters::CurveType::kNistP256,
                                   EcdsaParameters::HashType::kSha256,
                                   EcdsaParameters::SignatureEncoding::kDer,
                                   EcdsaParameters::Variant::kNoPrefix);
  const EcdsaPrivateKey& private_key =
      dynamic_cast<const EcdsaPrivateKey&>(*test_vector.signature_private_key);
  EcdsaPrivateKeyProto proto;
  proto.set_version(0);
  proto.set_key_value(private_key.GetPrivateKey(GetPartialKeyAccess())
                          .GetSecret(InsecureSecretKeyAccess::Get()));
  *proto.mutable_public_key() =
      ToEcdsaPublicKeyProto(private_key.GetPublicKey());
  return proto;
}

// Checks that a public key generaed by the SignKeyManager is considered valid.
TEST(EcdsaVerifyKeyManagerTest, PublicKeyValid) {
  EcdsaPublicKeyProto key = CreateValidPublicKey();
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP256) {
  EcdsaPublicKeyProto key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_hash_type(HashType::SHA512);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP384) {
  EcdsaPublicKeyProto key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P384);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateKeyBadHashP521) {
  EcdsaPublicKeyProto key = CreateValidPublicKey();
  EcdsaParams* params = key.mutable_params();
  params->set_curve(EllipticCurveType::NIST_P521);
  params->set_hash_type(HashType::SHA256);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParams) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA256);
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsHashP384) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA384);
  params.set_curve(EllipticCurveType::NIST_P384);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), IsOk());
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP256) {
  EcdsaParams params;
  params.set_hash_type(HashType::SHA512);
  params.set_curve(EllipticCurveType::NIST_P256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP384) {
  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P384);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaSignKeyManagerTest, ValidateParamsBadHashP521) {
  EcdsaParams params;
  params.set_curve(EllipticCurveType::NIST_P521);
  params.set_hash_type(HashType::SHA256);
  params.set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params), Not(IsOk()));
  EXPECT_THAT(EcdsaVerifyKeyManager().ValidateParams(params),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(EcdsaVerifyKeyManagerTest, Create) {
  EcdsaPrivateKeyProto private_key = CreateValidPrivateKey();
  EcdsaPublicKeyProto public_key = private_key.public_key();

  internal::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      EcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              IsOk());
}

TEST(EcdsaVerifyKeyManagerTest, CreateDifferentPrivateKey) {
  EcdsaPrivateKeyProto private_key = CreateValidPrivateKey();
  const internal::SignatureTestVector& test_vector_p384 =
      internal::GetEcdsaTestVector(
          EcdsaParameters::CurveType::kNistP384,
          EcdsaParameters::HashType::kSha384,
          EcdsaParameters::SignatureEncoding::kIeeeP1363,
          EcdsaParameters::Variant::kNoPrefix);
  const EcdsaPrivateKey& private_key_p384 =
      dynamic_cast<const EcdsaPrivateKey&>(
          *test_vector_p384.signature_private_key);
  EcdsaPublicKeyProto public_key =
      ToEcdsaPublicKeyProto(private_key_p384.GetPublicKey());

  internal::EcKey ec_key;
  ec_key.curve =
      Enums::ProtoToSubtle(private_key.public_key().params().curve());
  ec_key.pub_x = private_key.public_key().x();
  ec_key.pub_y = private_key.public_key().y();
  ec_key.priv = util::SecretDataFromStringView(private_key.key_value());

  auto direct_signer_or = subtle::EcdsaSignBoringSsl::New(
      ec_key,
      Enums::ProtoToSubtle(private_key.public_key().params().hash_type()),
      Enums::ProtoToSubtle(private_key.public_key().params().encoding()));
  ASSERT_THAT(direct_signer_or, IsOk());

  auto verifier_or =
      EcdsaVerifyKeyManager().GetPrimitive<PublicKeyVerify>(public_key);
  ASSERT_THAT(verifier_or, IsOk());

  std::string message = "Some message";
  EXPECT_THAT(verifier_or.value()->Verify(
                  direct_signer_or.value()->Sign(message).value(), message),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
