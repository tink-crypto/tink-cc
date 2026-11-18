// Copyright 2026 Google LLC
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

#include "tink/internal/legacy_key_manager_impl.h"

#include <memory>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/testing/test_only_asymmetric_parameters.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_private_key.h"
#include "tink/internal/testing/test_only_public_key.h"
#include "tink/key.h"
#include "tink/key_manager.h"
#include "tink/parameters.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/util/protobuf_helper.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::google::crypto::tink::TestOnlyKey;
using ::google::crypto::tink::TestOnlyKeyFormat;
using ::google::crypto::tink::internal::KeyDataTP;
using TestOnlyPrivateKeyProto = ::google::crypto::tink::TestOnlyPrivateKey;
using TestOnlyPublicKeyProto = ::google::crypto::tink::TestOnlyPublicKey;
using ::testing::Eq;
using ::testing::NotNull;

// Adaptor for a `PublicKeySign` key manager of `TestOnlyPrivateKey`s.
// Its primitives are `test::DummyPublicKeySign`s.
class TestOnlySignKeyManagerAdaptor
    : public LegacyKeyManagerAdaptor<PublicKeySign> {
 public:
  class PublicKeySignFactoryAdaptor : public LegacyPrivateKeyFactoryAdaptor {
    absl::string_view GetKeyFormatTypeName() const final {
      return "google.crypto.tink.TestOnlyKeyFormat";
    }

    absl::string_view GetPrivateKeyTypeName() const final {
      return "google.crypto.tink.TestOnlyPrivateKey";
    }

    absl::string_view GetPublicKeyTypeName() const final {
      return "google.crypto.tink.TestOnlyPublicKey";
    }

    std::unique_ptr<portable_proto::MessageLite>
    GetKeyFormatProtoDefaultInstance() const final {
      return std::make_unique<TestOnlyKeyFormat>();
    }

    std::unique_ptr<portable_proto::MessageLite>
    GetPrivateKeyProtoDefaultInstance() const final {
      return std::make_unique<TestOnlyPrivateKeyProto>();
    }

    absl::StatusOr<std::unique_ptr<Key>> CreateKey(
        const Parameters& parameters) const final {
      const TestOnlyAsymmetricParameters* asymmetric_parameters =
          dynamic_cast<const TestOnlyAsymmetricParameters*>(&parameters);
      if (asymmetric_parameters == nullptr) {
        return absl::InternalError("Unexpected parameters type.");
      }
      return CreateTestOnlyPrivateKey(*asymmetric_parameters,
                                      /*id_requirement=*/std::nullopt);
    }
  };

  TestOnlySignKeyManagerAdaptor()
      : key_factory_(std::make_unique<LegacyPrivateKeyFactoryImpl>(
            std::make_unique<PublicKeySignFactoryAdaptor>())) {}

  const std::string& GetKeyType() const final { return key_type_; }

  KeyDataTP::KeyMaterialTypeTP GetKeyMaterialType() const final {
    return KeyDataTP::KeyMaterialTypeTP::kAsymmetricPrivate;
  }

  const KeyFactory& GetKeyFactory() const final { return *key_factory_; }

  absl::StatusOr<std::unique_ptr<PublicKeySign>> GetPrimitive(
      const Key& key) const final {
    const TestOnlyPrivateKey* private_key =
        dynamic_cast<const TestOnlyPrivateKey*>(&key);
    if (private_key == nullptr) {
      return absl::InternalError("Unexpected key type.");
    }
    return NewTestOnlyPublicKeySign(*private_key);
  }

 private:
  const std::string key_type_ = std::string(kTestOnlyPrivateKeyTypeUrl);
  std::unique_ptr<KeyFactory> key_factory_;
};

// Adaptor for a `PublicKeyVerify` key manager of `TestOnlyPublicKey`s.
// Its primitives are `test::DummyPublicKeyVerify`s.
class TestOnlyVerifyKeyManagerAdaptor
    : public LegacyKeyManagerAdaptor<PublicKeyVerify> {
 public:
  TestOnlyVerifyKeyManagerAdaptor()
      : key_factory_(KeyFactory::AlwaysFailingFactory(
            absl::InternalError("Key generation is not supported."))) {}

  const std::string& GetKeyType() const final { return key_type_; }

  KeyDataTP::KeyMaterialTypeTP GetKeyMaterialType() const final {
    return KeyDataTP::KeyMaterialTypeTP::kAsymmetricPublic;
  }

  const KeyFactory& GetKeyFactory() const final { return *key_factory_; }

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> GetPrimitive(
      const Key& key) const final {
    const TestOnlyPublicKey* public_key =
        dynamic_cast<const TestOnlyPublicKey*>(&key);
    if (public_key == nullptr) {
      return absl::InternalError("Unexpected key type.");
    }
    return NewTestOnlyPublicKeyVerify(*public_key);
  }

 private:
  const std::string key_type_ = std::string(kTestOnlyPublicKeyTypeUrl);
  std::unique_ptr<KeyFactory> key_factory_;
};

TestOnlyKeyFormat GetKeyFormat() {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);
  return key_format;
}

// Tests for LegacyKeyManagerImpl.
//
// These tests use test-only key managers, since they test the conversion from
// key classes to the legacy KeyManager API, which doesn't depend on a specific
// algorithm.
class LegacyKeyManagerImplTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
    sign_key_manager_ = std::make_unique<LegacyKeyManagerImpl<PublicKeySign>>(
        std::make_unique<TestOnlySignKeyManagerAdaptor>());
    verify_key_manager_ =
        std::make_unique<LegacyKeyManagerImpl<PublicKeyVerify>>(
            std::make_unique<TestOnlyVerifyKeyManagerAdaptor>());
  }

  std::unique_ptr<KeyManager<PublicKeySign>> sign_key_manager_;
  std::unique_ptr<KeyManager<PublicKeyVerify>> verify_key_manager_;
};

TEST_F(LegacyKeyManagerImplTest, Basics) {
  EXPECT_THAT(sign_key_manager_->get_version(), Eq(0));
  EXPECT_THAT(sign_key_manager_->get_key_type(),
              Eq(kTestOnlyPrivateKeyTypeUrl));
}

TEST_F(LegacyKeyManagerImplTest, Factory_NewKey) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> key =
      factory.NewKey(GetKeyFormat());
  ASSERT_THAT(key, IsOk());

  auto private_key =
      portable_proto::DynamicCastMessage<TestOnlyPrivateKeyProto>(key->get());
  ASSERT_THAT(private_key, NotNull());
  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->key_value().size(), Eq(kTestOnlyKeySizeInBytes));
  EXPECT_THAT(private_key->public_key().version(), Eq(0));
  EXPECT_THAT(private_key->public_key().key_value().size(),
              Eq(kTestOnlyKeySizeInBytes));
}

TEST_F(LegacyKeyManagerImplTest, Factory_NewKey_SerializedKeyFormat) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> key =
      factory.NewKey(GetKeyFormat().SerializeAsString());
  ASSERT_THAT(key, IsOk());

  auto private_key =
      portable_proto::DynamicCastMessage<TestOnlyPrivateKeyProto>(key->get());
  ASSERT_THAT(private_key, NotNull());
  EXPECT_THAT(private_key->version(), Eq(0));
  EXPECT_THAT(private_key->key_value().size(), Eq(kTestOnlyKeySizeInBytes));
  EXPECT_THAT(private_key->public_key().version(), Eq(0));
  EXPECT_THAT(private_key->public_key().key_value().size(),
              Eq(kTestOnlyKeySizeInBytes));
}

TEST_F(LegacyKeyManagerImplTest, Factory_NewKeyData) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>> key_data =
      factory.NewKeyData(GetKeyFormat().SerializeAsString());
  ASSERT_THAT(key_data, IsOk());

  EXPECT_THAT((*key_data)->type_url(), Eq(kTestOnlyPrivateKeyTypeUrl));
  EXPECT_THAT((*key_data)->key_material_type(),
              Eq(google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE));

  TestOnlyPrivateKeyProto private_key;
  ASSERT_TRUE(private_key.ParseFromString((*key_data)->value()));
  EXPECT_THAT(private_key.version(), Eq(0));
  EXPECT_THAT(private_key.key_value().size(), Eq(kTestOnlyKeySizeInBytes));
  EXPECT_THAT(private_key.public_key().version(), Eq(0));
  EXPECT_THAT(private_key.public_key().key_value().size(),
              Eq(kTestOnlyKeySizeInBytes));
}

TEST_F(LegacyKeyManagerImplTest, Factory_NewKey_WrongKeyFormat) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();

  TestOnlyKey key_format;
  key_format.set_key_value("whatever");

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> key =
      factory.NewKey(key_format);
  EXPECT_THAT(key, StatusIs(absl::StatusCode::kInvalidArgument,
                            "Key format proto "
                            "'google.crypto.tink.TestOnlyKey' "
                            "is not supported by this key manager."));
}

TEST_F(LegacyKeyManagerImplTest, Factory_GetPublicKeyData) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();

  absl::StatusOr<std::unique_ptr<portable_proto::MessageLite>> key =
      factory.NewKey(GetKeyFormat().SerializeAsString());
  ASSERT_THAT(key, IsOk());
  auto private_key =
      portable_proto::DynamicCastMessage<TestOnlyPrivateKeyProto>(key->get());
  ASSERT_THAT(private_key, NotNull());

  const PrivateKeyFactory* private_factory =
      dynamic_cast<const PrivateKeyFactory*>(&factory);
  ASSERT_THAT(private_factory, NotNull());

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
      public_key_data =
          private_factory->GetPublicKeyData((*key)->SerializeAsString());
  ASSERT_THAT(public_key_data, IsOk());

  EXPECT_THAT((*public_key_data)->type_url(), Eq(kTestOnlyPublicKeyTypeUrl));
  EXPECT_THAT((*public_key_data)->key_material_type(),
              Eq(google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC));

  TestOnlyPublicKeyProto public_key;
  ASSERT_TRUE(public_key.ParseFromString((*public_key_data)->value()));
  EXPECT_THAT(public_key.key_value(),
              Eq(private_key->public_key().key_value()));
}

TEST_F(LegacyKeyManagerImplTest, Factory_GetPublicKeyData_InvalidKey) {
  const KeyFactory& factory = sign_key_manager_->get_key_factory();
  const PrivateKeyFactory* private_factory =
      dynamic_cast<const PrivateKeyFactory*>(&factory);
  ASSERT_THAT(private_factory, NotNull());

  absl::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
      public_key_data = private_factory->GetPublicKeyData("invalid");
  ASSERT_THAT(public_key_data, StatusIs(absl::StatusCode::kInvalidArgument,
                                        "Failed to parse the key"));
}

constexpr absl::string_view kPublicKeyBytes = "public key bytes";
constexpr absl::string_view kMessage = "message";

// Returns a private key proto whose public key bytes are `kPublicKeyBytes`.
TestOnlyPrivateKeyProto GetPrivateKeyProto() {
  TestOnlyPrivateKeyProto private_key;
  private_key.set_key_value(
      std::string(kPublicKeyBytes.rbegin(), kPublicKeyBytes.rend()));
  private_key.mutable_public_key()->set_key_value(kPublicKeyBytes);
  return private_key;
}

TEST_F(LegacyKeyManagerImplTest, GetPrimitive_KeyProto) {
  TestOnlyPublicKeyProto public_key;
  public_key.set_key_value(kPublicKeyBytes);

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      verify_key_manager_->GetPrimitive(public_key);
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      sign_key_manager_->GetPrimitive(GetPrivateKeyProto());
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(kMessage);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, kMessage), IsOk());
}

TEST_F(LegacyKeyManagerImplTest, GetPrimitive_KeyData) {
  TestOnlyPublicKeyProto public_key;
  public_key.set_key_value(kPublicKeyBytes);

  google::crypto::tink::KeyData key_data;
  key_data.set_type_url(kTestOnlyPublicKeyTypeUrl);
  key_data.set_key_material_type(
      google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC);
  key_data.set_value(public_key.SerializeAsString());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      verify_key_manager_->GetPrimitive(key_data);
  ASSERT_THAT(verifier, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
      sign_key_manager_->GetPrimitive(GetPrivateKeyProto());
  ASSERT_THAT(signer, IsOk());
  absl::StatusOr<std::string> signature = (*signer)->Sign(kMessage);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, kMessage), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
