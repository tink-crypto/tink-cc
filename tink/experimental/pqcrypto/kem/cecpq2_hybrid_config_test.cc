// Copyright 2021 Google LLC
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

#include "tink/experimental/pqcrypto/kem/cecpq2_hybrid_config.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "openssl/hrss.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/config/tink_fips.h"
#include "tink/crypto_format.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_aead_hkdf_private_key_manager.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_aead_hkdf_public_key_manager.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_hybrid_key_templates.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_parameters.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_private_key.h"
#include "tink/experimental/pqcrypto/kem/cecpq2_public_key.h"
#include "tink/experimental/pqcrypto/kem/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/tink_proto_structs.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"
#include "proto/xchacha20_poly1305.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::DummyHybridDecrypt;
using ::crypto::tink::test::DummyHybridEncrypt;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Cecpq2AeadHkdfParams;
using ::google::crypto::tink::Cecpq2AeadHkdfPrivateKey;
using ::google::crypto::tink::Cecpq2AeadHkdfPublicKey;
using ::google::crypto::tink::Cecpq2HkdfKemParams;
using ::google::crypto::tink::EcPointFormat;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::XChaCha20Poly1305KeyFormat;

class Cecpq2HybridConfigTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(Cecpq2HybridConfigTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  Cecpq2AeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  Cecpq2AeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(Cecpq2HybridConfigRegister(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridDecrypt>(
                  Cecpq2AeadHkdfPrivateKeyManager().get_key_type())
                  .status(),
              IsOk());
  EXPECT_THAT(Registry::get_key_manager<HybridEncrypt>(
                  Cecpq2AeadHkdfPublicKeyManager().get_key_type())
                  .status(),
              IsOk());
}

// Tests that the HybridEncrypt wrapper has been properly registered and we
// can wrap primitives
TEST_F(Cecpq2HybridConfigTest, EncryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Cecpq2HybridConfigRegister().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridEncrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridEncrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_THAT(wrapped, IsOk());
  auto encryption_result = wrapped.value()->Encrypt("secret", "");
  ASSERT_THAT(encryption_result, IsOk());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  EXPECT_EQ(
      encryption_result.value(),
      absl::StrCat(prefix,
                   DummyHybridEncrypt("dummy").Encrypt("secret", "").value()));
}

// Tests that the HybridDecrypt wrapper has been properly registered and we
// can wrap primitives
TEST_F(Cecpq2HybridConfigTest, DecryptWrapperRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  ASSERT_TRUE(Cecpq2HybridConfigRegister().ok());

  google::crypto::tink::KeysetInfo::KeyInfo key_info;
  key_info.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key_info.set_key_id(1234);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto primitive_set = absl::make_unique<PrimitiveSet<HybridDecrypt>>();
  ASSERT_THAT(
      primitive_set->set_primary(
          primitive_set
              ->AddPrimitive(absl::make_unique<DummyHybridDecrypt>("dummy"),
                             key_info)
              .value()),
      IsOk());

  auto wrapped = Registry::Wrap(std::move(primitive_set));

  ASSERT_THAT(wrapped, IsOk());

  std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
  std::string encryption =
      DummyHybridEncrypt("dummy").Encrypt("secret", "").value();

  ASSERT_EQ(
      wrapped.value()->Decrypt(absl::StrCat(prefix, encryption), "").value(),
      "secret");
}

std::shared_ptr<Parameters> CreateXChaCha20Poly1305Params() {
  absl::StatusOr<XChaCha20Poly1305Parameters> parameters =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  CHECK_OK(parameters);
  return absl::make_unique<XChaCha20Poly1305Parameters>(*parameters);
}

TEST_F(Cecpq2HybridConfigTest, Cecpq2ProtoParamsSerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<internal::ProtoParametersSerialization>
      proto_params_serialization =
          internal::ProtoParametersSerialization::Create(
              Cecpq2HybridKeyTemplateX25519HkdfHmacSha256XChaCha20Poly1305());
  ASSERT_THAT(proto_params_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Cecpq2Parameters> params =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params.status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Cecpq2HybridConfigRegister(), IsOk());

  absl::StatusOr<std::unique_ptr<Parameters>> parsed_params2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *proto_params_serialization);
  ASSERT_THAT(parsed_params2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_params2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(*params);
  ASSERT_THAT(serialized_params2, IsOk());
}

KeyTemplate GetXChaCha20Poly1305RawKeyTemplate() {
  XChaCha20Poly1305KeyFormat key_format;
  key_format.set_version(0);
  KeyTemplate key_template;
  key_template.set_type_url(
      "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
  key_template.set_value(key_format.SerializeAsString());
  key_template.set_output_prefix_type(OutputPrefixType::RAW);
  return key_template;
}

Cecpq2AeadHkdfParams CreateParamsProto() {
  Cecpq2HkdfKemParams kem_params_proto;
  kem_params_proto.set_curve_type(EllipticCurveType::CURVE25519);
  kem_params_proto.set_ec_point_format(EcPointFormat::COMPRESSED);
  kem_params_proto.set_hkdf_hash_type(HashType::SHA256);
  kem_params_proto.set_hkdf_salt("salt");

  Cecpq2AeadHkdfParams params_proto;
  *params_proto.mutable_kem_params() = kem_params_proto;
  *params_proto.mutable_dem_params()->mutable_aead_dem() =
      GetXChaCha20Poly1305RawKeyTemplate();

  return params_proto;
}

TEST_F(Cecpq2HybridConfigTest, Cecpq2ProtoPublicKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  const std::string x25519_public_key_bytes =
      subtle::Random::GetRandomBytes(internal::X25519KeyPubKeySize());
  const std::string hrss_public_key_bytes =
      subtle::Random::GetRandomBytes(HRSS_PUBLIC_KEY_BYTES);

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = CreateParamsProto();
  public_key_proto.set_x25519_public_key_x(x25519_public_key_bytes);
  public_key_proto.set_hrss_public_key_marshalled(hrss_public_key_bytes);
  RestrictedData serialized_public_key = RestrictedData(
      public_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPublicKey",
          serialized_public_key,
          internal::KeyMaterialTypeEnum::kAsymmetricPublic,
          internal::OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Cecpq2Parameters> params =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*params)
          .SetX25519PublicKeyBytes(x25519_public_key_bytes)
          .SetHrssPublicKeyBytes(hrss_public_key_bytes)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Cecpq2HybridConfigRegister(), IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key2 =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, /*token=*/absl::nullopt);
  ASSERT_THAT(parsed_key2, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key2 =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *public_key, /*token=*/absl::nullopt);
  ASSERT_THAT(serialized_key2, IsOk());
}

TEST_F(Cecpq2HybridConfigTest, Cecpq2ProtoPrivateKeySerializationRegistered) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  absl::StatusOr<crypto::tink::pqc::Cecpq2KeyPair> cecpq2_key_pair =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  ASSERT_THAT(cecpq2_key_pair, IsOk());

  Cecpq2AeadHkdfPublicKey public_key_proto;
  public_key_proto.set_version(0);
  *public_key_proto.mutable_params() = CreateParamsProto();
  public_key_proto.set_x25519_public_key_x(
      cecpq2_key_pair->x25519_key_pair.pub_x);
  public_key_proto.set_hrss_public_key_marshalled(
      cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled);

  Cecpq2AeadHkdfPrivateKey private_key_proto;
  private_key_proto.set_version(0);
  *private_key_proto.mutable_public_key() = public_key_proto;
  private_key_proto.set_x25519_private_key(
      util::SecretDataAsStringView(cecpq2_key_pair->x25519_key_pair.priv));
  private_key_proto.set_hrss_private_key_seed(util::SecretDataAsStringView(
      cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed));
  RestrictedData serialized_private_key = RestrictedData(
      private_key_proto.SerializeAsString(), InsecureSecretKeyAccess::Get());

  absl::StatusOr<internal::ProtoKeySerialization> proto_key_serialization =
      internal::ProtoKeySerialization::Create(
          "type.googleapis.com/google.crypto.tink.Cecpq2AeadHkdfPrivateKey",
          RestrictedData(private_key_proto.SerializeAsString(),
                         InsecureSecretKeyAccess::Get()),
          internal::KeyMaterialTypeEnum::kAsymmetricPrivate,
          internal::OutputPrefixTypeEnum::kRaw,
          /*id_requirement=*/absl::nullopt);
  ASSERT_THAT(proto_key_serialization, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> parsed_key =
      internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
          *proto_key_serialization, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_key.status(), StatusIs(absl::StatusCode::kNotFound));

  absl::StatusOr<Cecpq2Parameters> params =
      Cecpq2Parameters::Create(*CreateXChaCha20Poly1305Params(), "salt",
                               Cecpq2Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<Cecpq2PublicKey> public_key =
      Cecpq2PublicKey::Builder()
          .SetParameters(*params)
          .SetX25519PublicKeyBytes(cecpq2_key_pair->x25519_key_pair.pub_x)
          .SetHrssPublicKeyBytes(
              cecpq2_key_pair->hrss_key_pair.hrss_public_key_marshaled)
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<Cecpq2PrivateKey> private_key =
      Cecpq2PrivateKey::Builder()
          .SetPublicKey(*public_key)
          .SetX25519PrivateKeyBytes(
              RestrictedData(cecpq2_key_pair->x25519_key_pair.priv,
                             InsecureSecretKeyAccess::Get()))
          .SetHrssPrivateKeySeed(RestrictedData(
              cecpq2_key_pair->hrss_key_pair.hrss_private_key_seed,
              InsecureSecretKeyAccess::Get()))
          .Build(GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  absl::StatusOr<std::unique_ptr<Serialization>> serialized_key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeKey<internal::ProtoKeySerialization>(
              *private_key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialized_key.status(), StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Cecpq2HybridConfigRegister(), IsOk());

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
