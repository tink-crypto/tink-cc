// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/internal/key_gen_configuration_impl.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_key_managers.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_manager.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssParams;
using RsaSsaPssPrivateKeyProto = ::google::crypto::tink::RsaSsaPssPrivateKey;
using RsaSsaPssPublicKeyProto = ::google::crypto::tink::RsaSsaPssPublicKey;
using ::testing::Eq;
using ::testing::NotNull;

class FakePrimitive {
 public:
  explicit FakePrimitive(absl::string_view s) : s_(s) {}
  std::string get() { return s_; }

 private:
  std::string s_;
};

class FakeKeyTypeManager
    : public KeyTypeManager<AesGcmKeyProto, AesGcmKeyFormat,
                            List<FakePrimitive>> {
 public:
  class FakePrimitiveFactory : public PrimitiveFactory<FakePrimitive> {
   public:
    absl::StatusOr<std::unique_ptr<FakePrimitive>> Create(
        const AesGcmKeyProto& key) const override {
      return std::make_unique<FakePrimitive>(key.key_value());
    }
  };

  FakeKeyTypeManager()
      : KeyTypeManager(std::make_unique<FakePrimitiveFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(const AesGcmKeyProto& key) const override {
    return absl::OkStatus();
  }

  absl::Status ValidateKeyFormat(
      const AesGcmKeyFormat& key_format) const override {
    return absl::OkStatus();
  }

  absl::StatusOr<AesGcmKeyProto> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    return AesGcmKeyProto();
  }

  absl::StatusOr<AesGcmKeyProto> DeriveKey(
      const AesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    return AesGcmKeyProto();
  }

 private:
  const std::string key_type_ =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
};

TEST(KeyGenConfigurationImplTest, AddKeyTypeManager) {
  KeyGenConfiguration config;
  EXPECT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<FakeKeyTypeManager>(), config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, AddLegacyKeyManager) {
  KeyGenConfiguration config;
  FakeKeyTypeManager manager;
  EXPECT_THAT(KeyGenConfigurationImpl::AddLegacyKeyManager(
                  MakeKeyManager<FakePrimitive>(&manager), config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, AddKeyCreator) {
  KeyGenConfiguration config;
  EXPECT_THAT(KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
                  CreateTestOnlyKey, config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, GetKeyTypeInfoStore) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<FakeKeyTypeManager>(), config),
              IsOk());

  EXPECT_THAT(KeyGenConfigurationImpl::GetKeyTypeInfoStore(config), IsOk());
}

TEST(KeyGenConfigurationImplTest, GetKeyTypeManager) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<FakeKeyTypeManager>(), config),
              IsOk());

  std::string type_url = FakeKeyTypeManager().get_key_type();
  absl::StatusOr<const KeyTypeInfoStore*> store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());
  absl::StatusOr<const KeyTypeInfoStore::Info*> info = (*store)->Get(type_url);
  ASSERT_THAT(info, IsOk());

  absl::StatusOr<const KeyManager<FakePrimitive>*> key_manager =
      (*info)->get_key_manager<FakePrimitive>(type_url);
  ASSERT_THAT(key_manager, IsOk());
  EXPECT_EQ((*key_manager)->get_key_type(), type_url);
}

TEST(KeyGenConfigurationImplTest, GetLegacyKeyManager) {
  KeyGenConfiguration config;
  FakeKeyTypeManager manager;
  ASSERT_THAT(KeyGenConfigurationImpl::AddLegacyKeyManager(
                  MakeKeyManager<FakePrimitive>(&manager), config),
              IsOk());

  absl::StatusOr<const KeyTypeInfoStore*> store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());
  std::string type_url = FakeKeyTypeManager().get_key_type();
  absl::StatusOr<const KeyTypeInfoStore::Info*> info = (*store)->Get(type_url);
  ASSERT_THAT(info, IsOk());

  absl::StatusOr<const KeyManager<FakePrimitive>*> key_manager =
      (*info)->get_key_manager<FakePrimitive>(type_url);
  ASSERT_THAT(key_manager, IsOk());
  EXPECT_EQ((*key_manager)->get_key_type(), type_url);
}

TEST(KeyGenConfigurationImplTest, CreateKey) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
                  CreateTestOnlyKey, config),
              IsOk());

  absl::StatusOr<TestOnlyParameters> params =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<Key>> generic_key =
      KeyGenConfigurationImpl::CreateKey(*params,
                                         /*id_requirement=*/0x02030400, config);
  ASSERT_THAT(generic_key, IsOk());
  const TestOnlySymmetricKey* key =
      dynamic_cast<const TestOnlySymmetricKey*>(generic_key->get());

  ASSERT_THAT(key, NotNull());
  EXPECT_THAT(key->GetIdRequirement(), Eq(0x02030400));
  EXPECT_THAT(key->GetOutputPrefix(),
              Eq(std::string("\x01\x02\x03\x04\x00", 5)));
  EXPECT_THAT(key->GetParameters(), Eq(*params));
  EXPECT_THAT(key->GetKeyBytes(GetPartialKeyAccess()).size(),
              Eq(kTestOnlyKeySizeInBytes));
}

TEST(KeyGenConfigurationImplTest, CreateKeyWithMissingKeyCreatorFails) {
  KeyGenConfiguration config;

  absl::StatusOr<TestOnlyParameters> params =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  ASSERT_THAT(params, IsOk());

  EXPECT_THAT(
      KeyGenConfigurationImpl::CreateKey(*params,
                                         /*id_requirement=*/0x02030400, config)
          .status(),
      StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(KeyGenConfigurationImplTest, GetMissingKeyManagerFails) {
  KeyGenConfiguration config;
  absl::StatusOr<const KeyTypeInfoStore*> store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());
  EXPECT_THAT((*store)->Get("i.do.not.exist").status(),
              StatusIs(absl::StatusCode::kNotFound));
}

class FakeSignKeyManager
    : public PrivateKeyTypeManager<RsaSsaPssPrivateKeyProto, RsaSsaPssKeyFormat,
                                   RsaSsaPssPublicKeyProto,
                                   List<PublicKeySign>> {
 public:
  class PublicKeySignFactory : public PrimitiveFactory<PublicKeySign> {
   public:
    absl::StatusOr<std::unique_ptr<PublicKeySign>> Create(
        const RsaSsaPssPrivateKeyProto& key) const override {
      return {std::make_unique<test::DummyPublicKeySign>("a public key sign")};
    }
  };

  explicit FakeSignKeyManager()
      : PrivateKeyTypeManager(std::make_unique<PublicKeySignFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::ASYMMETRIC_PRIVATE;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(const RsaSsaPssPrivateKeyProto& key) const override {
    return absl::OkStatus();
  }

  absl::Status ValidateKeyFormat(
      const RsaSsaPssKeyFormat& key_format) const override {
    return absl::OkStatus();
  }

  absl::StatusOr<RsaSsaPssPrivateKeyProto> CreateKey(
      const RsaSsaPssKeyFormat& key_format) const override {
    return RsaSsaPssPrivateKeyProto();
  }

  absl::StatusOr<RsaSsaPssPrivateKeyProto> DeriveKey(
      const RsaSsaPssKeyFormat& key_format,
      InputStream* input_stream) const override {
    return RsaSsaPssPrivateKeyProto();
  }

  absl::StatusOr<RsaSsaPssPublicKeyProto> GetPublicKey(
      const RsaSsaPssPrivateKeyProto& private_key) const override {
    return private_key.public_key();
  }

 private:
  const std::string key_type_ = "some.sign.key.type";
};

class FakeVerifyKeyManager
    : public KeyTypeManager<RsaSsaPssPublicKeyProto, void,
                            List<PublicKeyVerify>> {
 public:
  class PublicKeyVerifyFactory : public PrimitiveFactory<PublicKeyVerify> {
   public:
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Create(
        const RsaSsaPssPublicKeyProto& key) const override {
      return {
          std::make_unique<test::DummyPublicKeyVerify>("a public key verify")};
    }
  };

  explicit FakeVerifyKeyManager()
      : KeyTypeManager(std::make_unique<PublicKeyVerifyFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::ASYMMETRIC_PUBLIC;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(const RsaSsaPssPublicKeyProto& key) const override {
    return absl::OkStatus();
  }

  absl::Status ValidateParams(const RsaSsaPssParams& params) const {
    return absl::OkStatus();
  }

 private:
  const std::string key_type_ = "some.verify.key.type";
};

TEST(KeyGenConfigurationImplTest, AddAsymmetricKeyManagers) {
  KeyGenConfiguration config;
  EXPECT_THAT(KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  std::make_unique<FakeSignKeyManager>(),
                  std::make_unique<FakeVerifyKeyManager>(), config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, GetAsymmetricKeyManagers) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  std::make_unique<FakeSignKeyManager>(),
                  std::make_unique<FakeVerifyKeyManager>(), config),
              IsOk());

  {
    std::string type_url = FakeSignKeyManager().get_key_type();
    absl::StatusOr<const KeyTypeInfoStore*> store =
        KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    ASSERT_THAT(store, IsOk());
    absl::StatusOr<const KeyTypeInfoStore::Info*> info =
        (*store)->Get(type_url);
    ASSERT_THAT(info, IsOk());

    absl::StatusOr<const KeyManager<PublicKeySign>*> key_manager =
        (*info)->get_key_manager<PublicKeySign>(type_url);
    ASSERT_THAT(key_manager, IsOk());
    EXPECT_EQ((*key_manager)->get_key_type(), type_url);
  }
  {
    std::string type_url = FakeVerifyKeyManager().get_key_type();
    absl::StatusOr<const KeyTypeInfoStore*> store =
        KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    ASSERT_THAT(store, IsOk());
    absl::StatusOr<const KeyTypeInfoStore::Info*> info =
        (*store)->Get(type_url);
    ASSERT_THAT(info, IsOk());

    absl::StatusOr<const KeyManager<PublicKeyVerify>*> key_manager =
        (*info)->get_key_manager<PublicKeyVerify>(type_url);
    ASSERT_THAT(key_manager, IsOk());
    EXPECT_EQ((*key_manager)->get_key_type(), type_url);
  }
}

TEST(KeyGenConfigurationImplTest, GlobalRegistryMode) {
  Registry::Reset();
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::SetGlobalRegistryMode(config), IsOk());
  EXPECT_TRUE(KeyGenConfigurationImpl::IsInGlobalRegistryMode(config));

  // Check that KeyGenConfigurationImpl functions return kFailedPrecondition.
  EXPECT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<FakeKeyTypeManager>(), config),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  std::make_unique<FakeSignKeyManager>(),
                  std::make_unique<FakeVerifyKeyManager>(), config),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  FakeKeyTypeManager manager;
  EXPECT_THAT(KeyGenConfigurationImpl::AddLegacyKeyManager(
                  MakeKeyManager<FakePrimitive>(&manager), config),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
                  CreateTestOnlyKey, config),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(KeyGenConfigurationImpl::GetKeyTypeInfoStore(config).status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));

  EXPECT_THAT(KeysetHandle::GenerateNew(TestOnlyKeyTemplate(), config).status(),
              StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  std::make_unique<TestOnlyKeyTypeManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  EXPECT_THAT(KeysetHandle::GenerateNew(TestOnlyKeyTemplate(), config).status(),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, GlobalRegistryModeWithNonEmptyConfigFails) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  std::make_unique<FakeKeyTypeManager>(), config),
              IsOk());
  EXPECT_THAT(KeyGenConfigurationImpl::SetGlobalRegistryMode(config),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_FALSE(KeyGenConfigurationImpl::IsInGlobalRegistryMode(config));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
