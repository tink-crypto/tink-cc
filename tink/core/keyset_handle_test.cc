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

#include "tink/keyset_handle.h"

#include <cstdint>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aead_wrapper.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/internal/key_gen_config_v0.h"
#include "tink/aead/xchacha20_poly1305_key.h"
#include "tink/aead/xchacha20_poly1305_parameters.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/config/fips_140_2.h"
#include "tink/config/global_registry.h"
#include "tink/config/key_gen_fips_140_2.h"
#include "tink/config/tink_config.h"
#include "tink/configuration.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/ssl_util.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_reader.h"
#include "tink/partial_key_access.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/signature/ecdsa_proto_serialization.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/subtle/random.h"
#include "tink/subtle/xchacha20_poly1305_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::TestKeysetHandle;
using ::crypto::tink::test::AddKeyData;
using ::crypto::tink::test::AddLegacyKey;
using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using AesGcmSivKeyProto = ::google::crypto::tink::AesGcmSivKey;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::SizeIs;
using ::testing::TestWithParam;
using ::testing::Values;

namespace {

class KeysetHandleTest : public ::testing::Test {
 protected:
  void SetUp() override {
    Registry::Reset();
    auto status = TinkConfig::Register();
    ASSERT_TRUE(status.ok()) << status;

    internal::UnSetFipsRestricted();
  }
};

using KeysetHandleDeathTest = KeysetHandleTest;

// Fake AEAD key type manager for testing.
class FakeAeadKeyManager
    : public KeyTypeManager<AesGcmKeyProto, AesGcmKeyFormat, List<Aead>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
   public:
    explicit AeadFactory(absl::string_view key_type) : key_type_(key_type) {}

    absl::StatusOr<std::unique_ptr<Aead>> Create(
        const AesGcmKeyProto& key) const override {
      return {absl::make_unique<DummyAead>(key_type_)};
    }

   private:
    const std::string key_type_;
  };

  explicit FakeAeadKeyManager(absl::string_view key_type)
      : KeyTypeManager(absl::make_unique<AeadFactory>(key_type)),
        key_type_(key_type) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
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
  const std::string key_type_;
};

class MockAeadPrimitiveWrapper : public PrimitiveWrapper<Aead, Aead> {
 public:
  MOCK_METHOD(absl::StatusOr<std::unique_ptr<Aead>>, Wrap,
              (std::unique_ptr<PrimitiveSet<Aead>> primitive_set),
              (const, override));
};

// Generates a keyset for testing.
Keyset GetTestKeyset() {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  return keyset;
}

// Generates a public keyset for testing.
Keyset GetPublicTestKeyset() {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::REMOTE, &keyset);
  keyset.set_primary_key_id(42);
  return keyset;
}

// Creates an XChaCha20Poly1305Key from the given parameters.
absl::StatusOr<std::unique_ptr<XChaCha20Poly1305Key>>
CreateXChaCha20Poly1305Key(const XChaCha20Poly1305Parameters& params,
                           absl::optional<int> id_requirement) {
  RestrictedData secret = RestrictedData(/*num_random_bytes=*/32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      params.GetVariant(), secret, id_requirement, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<crypto::tink::XChaCha20Poly1305Key>(*key);
}

absl::StatusOr<std::unique_ptr<Aead>> GetPrimitiveForXChaCha20Poly1305Key(
    const XChaCha20Poly1305Key& key) {
  return subtle::XChacha20Poly1305BoringSsl::New(
      (key.GetKeyBytes(GetPartialKeyAccess())
           .Get(InsecureSecretKeyAccess::Get())));
}

// NOTE: Avoid adding key types that are only available via OpenSSL.
const KeyGenConfiguration& TestKeyGenConfig() {
  static const KeyGenConfiguration* instance = [] {
    static KeyGenConfiguration* config = new KeyGenConfiguration();
    CHECK_OK(internal::AddAeadKeyGenV0(*config));
    CHECK_OK(RegisterEcdsaProtoSerialization());
    CHECK_OK(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
        absl::make_unique<EcdsaSignKeyManager>(),
        absl::make_unique<EcdsaVerifyKeyManager>(), *config));

    return config;
  }();
  return *instance;
}

TEST_F(KeysetHandleTest, DefaultCtor) {
  KeysetHandle keyset_handle;
  EXPECT_THAT(keyset_handle.size(), Eq(0));
  EXPECT_THAT(keyset_handle.Validate(), Not(IsOk()));
  EXPECT_THAT(
      keyset_handle.GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
      Not(IsOk()));
}

TEST_F(KeysetHandleTest, CopyCtorAndAssignment) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::ReadNoSecret(GetPublicTestKeyset().SerializeAsString());
  ASSERT_THAT(keyset_handle, IsOk());
  ASSERT_THAT(*keyset_handle, NotNull());
  ASSERT_THAT((*keyset_handle)->Validate(), IsOk());
  EXPECT_THAT((*keyset_handle)->size(), Eq(2));
  EXPECT_THAT((*keyset_handle)->GetPrimary().GetId(), Eq(42));
  KeysetHandle keyset_handle_copy = **keyset_handle;
  EXPECT_THAT(keyset_handle_copy.Validate(), IsOk());
  EXPECT_EQ(keyset_handle_copy.size(), (*keyset_handle)->size());
  EXPECT_THAT(keyset_handle_copy.GetPrimary().GetId(),
              Eq((*keyset_handle)->GetPrimary().GetId()));
  KeysetHandle keyset_handle_copy2;
  EXPECT_THAT(keyset_handle_copy2.Validate(), Not(IsOk()));
  EXPECT_THAT(keyset_handle_copy2.size(), Eq(0));
  keyset_handle_copy2 = keyset_handle_copy;
  EXPECT_THAT(keyset_handle_copy2.Validate(), IsOk());
  EXPECT_EQ(keyset_handle_copy2.size(), (*keyset_handle)->size());
  EXPECT_THAT(keyset_handle_copy2.GetPrimary().GetId(),
              Eq((*keyset_handle)->GetPrimary().GetId()));
}

TEST_F(KeysetHandleTest, MoveCtorAndAssignment) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::ReadNoSecret(GetPublicTestKeyset().SerializeAsString());
  ASSERT_THAT(keyset_handle, IsOk());
  ASSERT_THAT(*keyset_handle, NotNull());
  ASSERT_THAT((*keyset_handle)->Validate(), IsOk());
  EXPECT_THAT((*keyset_handle)->size(), Eq(2));
  EXPECT_THAT((*keyset_handle)->GetPrimary().GetId(), Eq(42));
  KeysetHandle keyset_handle_moved = std::move(**keyset_handle);
  // Moved out handle becomes empty
  EXPECT_THAT((*keyset_handle)->Validate(), Not(IsOk()));
  EXPECT_THAT((*keyset_handle)->size(), Eq(0));
  // Moved to handle is valid and contains expected values
  EXPECT_THAT(keyset_handle_moved.Validate(), IsOk());
  EXPECT_THAT(keyset_handle_moved.size(), Eq(2));
  EXPECT_THAT(keyset_handle_moved.GetPrimary().GetId(), Eq(42));
  KeysetHandle keyset_handle_moved2;
  EXPECT_THAT(keyset_handle_moved2.Validate(), Not(IsOk()));
  EXPECT_THAT(keyset_handle_moved2.size(), Eq(0));
  keyset_handle_moved2 = std::move(keyset_handle_moved);
  // Moved out handle becomes empty
  EXPECT_THAT(keyset_handle_moved.Validate(), Not(IsOk()));
  EXPECT_THAT(keyset_handle_moved.size(), Eq(0));
  // Moved to handle is valid and contains expected values
  EXPECT_THAT(keyset_handle_moved2.Validate(), IsOk());
  EXPECT_THAT(keyset_handle_moved2.size(), Eq(2));
  EXPECT_THAT(keyset_handle_moved2.GetPrimary().GetId(), Eq(42));
}

TEST_F(KeysetHandleTest, ReadEncryptedKeysetBinary) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  {  // Good encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext =
        aead.Encrypt(keyset.SerializeAsString(), /* associated_data= */ "")
            .value();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(
        BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_TRUE(result.ok()) << result.status();
    auto handle = std::move(result.value());
    EXPECT_EQ(keyset.SerializeAsString(),
              TestKeysetHandle::GetKeyset(*handle).SerializeAsString());
  }

  {  // AEAD does not match the ciphertext
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext =
        aead.Encrypt(keyset.SerializeAsString(), /* associated_data= */ "")
            .value();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(
        BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
    DummyAead wrong_aead("wrong aead");
    auto result = KeysetHandle::Read(std::move(reader), wrong_aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  }

  {  // Ciphertext does not contain actual keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext =
        aead.Encrypt("not a serialized keyset", /* associated_data= */ "")
            .value();
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(
        BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  }

  {  // Wrong ciphertext of encrypted keyset.
    DummyAead aead("dummy aead 42");
    std::string keyset_ciphertext = "totally wrong ciphertext";
    EncryptedKeyset encrypted_keyset;
    encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
    auto reader = std::move(
        BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
    auto result = KeysetHandle::Read(std::move(reader), aead);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  }
}

// Check that the generated keyset handle correctly propagates annotations.
TEST_F(KeysetHandleTest, ReadEncryptedWithAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};
  Keyset keyset = GetTestKeyset();
  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext =
      *aead.Encrypt(keyset.SerializeAsString(), /*associated_data=*/"");
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(encrypted_keyset.SerializeAsString());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::Read(*std::move(reader), aead, kAnnotations);
  ASSERT_THAT(keyset_handle, IsOk());

  // In order to validate annotations are set correctly, we need acceess to the
  // generated primitive set, which is populated by KeysetWrapperImpl and passed
  // to the primitive wrapper. We thus register a mock primitive wrapper for
  // Aead so that we can copy the annotations and later check them.
  auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(*primitive_wrapper, Wrap(_))
      .WillOnce(
          [&generated_annotations](
              std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
            generated_annotations = generated_primitive_set->get_annotations();
            std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>("");
            return aead;
          });
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_other_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());

  ASSERT_THAT((*keyset_handle)
                  ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
              IsOk());
  EXPECT_EQ(generated_annotations, kAnnotations);
  // This is needed to cleanup mocks.
  Registry::Reset();
}

TEST_F(KeysetHandleTest, ReadEncryptedKeysetWithAssociatedDataGoodKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), "aad").value();
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
  std::unique_ptr<KeysetReader> reader = std::move(
      BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> result =
      KeysetHandle::ReadWithAssociatedData(std::move(reader), aead, "aad");
  EXPECT_THAT(result, IsOk());
  auto handle = std::move(result.value());
  EXPECT_EQ(keyset.SerializeAsString(),
            TestKeysetHandle::GetKeyset(*handle).SerializeAsString());
}

// Check that the generated keyset handle correctly propagates annotations.
TEST_F(KeysetHandleTest, ReadEncryptedWithAssociatedDataAndAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};
  constexpr absl::string_view kAssociatedData = "some associated data";
  Keyset keyset = GetTestKeyset();
  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext =
      *aead.Encrypt(keyset.SerializeAsString(), kAssociatedData);
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(encrypted_keyset.SerializeAsString());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::ReadWithAssociatedData(*std::move(reader), aead,
                                           kAssociatedData, kAnnotations);
  ASSERT_THAT(keyset_handle, IsOk());

  auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(*primitive_wrapper, Wrap(_))
      .WillOnce(
          [&generated_annotations](
              std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
            generated_annotations = generated_primitive_set->get_annotations();
            std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>("");
            return aead;
          });
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_other_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());

  ASSERT_THAT((*keyset_handle)
                  ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
              IsOk());
  EXPECT_EQ(generated_annotations, kAnnotations);
  // This is needed to cleanup mocks.
  Registry::Reset();
}

TEST_F(KeysetHandleTest, ReadEncryptedKeysetWithAssociatedDataWrongAad) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), "aad").value();
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
  auto reader = std::move(
      BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
  auto result = KeysetHandle::ReadWithAssociatedData(std::move(reader), aead,
                                                     "different");
  EXPECT_THAT(result, Not(IsOk()));
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
}

TEST_F(KeysetHandleTest, ReadEncryptedKeysetWithAssociatedDataEmptyAad) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  DummyAead aead("dummy aead 42");
  std::string keyset_ciphertext =
      aead.Encrypt(keyset.SerializeAsString(), "aad").value();
  EncryptedKeyset encrypted_keyset;
  encrypted_keyset.set_encrypted_keyset(keyset_ciphertext);
  auto reader = std::move(
      BinaryKeysetReader::New(encrypted_keyset.SerializeAsString()).value());
  auto result = KeysetHandle::Read(std::move(reader), aead);
  EXPECT_THAT(result, Not(IsOk()));
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
}

TEST_F(KeysetHandleTest, WriteEncryptedKeysetWithAssociatedData) {
  // Prepare a valid keyset handle
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  auto reader =
      std::move(BinaryKeysetReader::New(keyset.SerializeAsString()).value());
  auto keyset_handle =
      std::move(CleartextKeysetHandle::Read(std::move(reader)).value());

  // Prepare a keyset writer.
  DummyAead aead("dummy aead 42");
  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      std::move(BinaryKeysetWriter::New(std::move(destination_stream)).value());

  // Write the keyset handle and check the result.
  auto status =
      keyset_handle->WriteWithAssociatedData(writer.get(), aead, "aad");
  EXPECT_TRUE(status.ok()) << status;
  auto reader_result = BinaryKeysetReader::New(buffer.str());
  EXPECT_TRUE(reader_result.ok()) << reader_result.status();
  auto read_encrypted_result = reader_result.value()->ReadEncrypted();
  EXPECT_TRUE(read_encrypted_result.ok()) << read_encrypted_result.status();
  auto encrypted_keyset = std::move(read_encrypted_result.value());
  auto decrypt_result =
      aead.Decrypt(encrypted_keyset->encrypted_keyset(), "aad");
  EXPECT_TRUE(decrypt_result.status().ok()) << decrypt_result.status();
  auto decrypted = decrypt_result.value();
  EXPECT_EQ(decrypted, keyset.SerializeAsString());

  // Try writing to a null-writer.
  status = keyset_handle->Write(nullptr, aead);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
}

TEST_F(KeysetHandleTest, GenerateNew) {
  const google::crypto::tink::KeyTemplate* templates[] = {
      &AeadKeyTemplates::Aes128Gcm(),
      &AeadKeyTemplates::Aes256Gcm(),
      &AeadKeyTemplates::Aes128CtrHmacSha256(),
      &AeadKeyTemplates::Aes256CtrHmacSha256(),
  };
  for (auto templ : templates) {
    EXPECT_THAT(KeysetHandle::GenerateNew(*templ, TestKeyGenConfig()).status(),
                IsOk());
    EXPECT_THAT(KeysetHandle::GenerateNew(*templ, TestKeyGenConfig()).status(),
                IsOk());
  }
}

TEST_F(KeysetHandleTest, GenerateNewWithBespokeConfig) {
  KeyGenConfiguration config;
  EXPECT_THAT(
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), config).status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), config),
              IsOk());
  EXPECT_THAT(
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), config).status(),
      IsOk());
}

TEST_F(KeysetHandleTest, GenerateNewWithGlobalRegistryConfig) {
  EXPECT_THAT(KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                        KeyGenConfigGlobalRegistry()),
              IsOk());
}

TEST_F(KeysetHandleTest, GenerateNewWithAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};

  // `handle` depends on the global registry.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry(), kAnnotations);
  ASSERT_THAT(handle, IsOk());

  // `config_handle` uses a config that depends on the global registry.
  absl::StatusOr<std::unique_ptr<KeysetHandle>> config_handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry(), kAnnotations);
  ASSERT_THAT(config_handle, IsOk());

  for (KeysetHandle h : {**handle, **config_handle}) {
    auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
    absl::flat_hash_map<std::string, std::string> generated_annotations;
    EXPECT_CALL(*primitive_wrapper, Wrap(_))
        .WillOnce(
            [&generated_annotations](
                std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
              generated_annotations =
                  generated_primitive_set->get_annotations();
              std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>("");
              return aead;
            });

    Registry::Reset();
    ASSERT_THAT(
        Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
        IsOk());
    ASSERT_THAT(Registry::RegisterKeyTypeManager(
                    absl::make_unique<FakeAeadKeyManager>(
                        "type.googleapis.com/google.crypto.tink.AesGcmKey"),
                    /*new_key_allowed=*/true),
                IsOk());

    EXPECT_THAT(h.GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
                IsOk());
    EXPECT_EQ(generated_annotations, kAnnotations);

    // This is needed to cleanup mocks.
    Registry::Reset();
  }
}

TEST_F(KeysetHandleTest, GenerateNewInvalidKeyTemplateFails) {
  KeyTemplate templ;
  templ.set_type_url("type.googleapis.com/some.unknown.KeyType");
  templ.set_output_prefix_type(OutputPrefixType::TINK);

  auto handle_result = KeysetHandle::GenerateNew(templ, TestKeyGenConfig());
  EXPECT_FALSE(handle_result.ok());
  EXPECT_EQ(absl::StatusCode::kNotFound, handle_result.status().code());
}

using KeysetHandlePrefixTest =
    TestWithParam<XChaCha20Poly1305Parameters::Variant>;

INSTANTIATE_TEST_SUITE_P(
    KeysetHandlePrefixTestSuite, KeysetHandlePrefixTest,
    Values(XChaCha20Poly1305Parameters::Variant::kTink,
           XChaCha20Poly1305Parameters::Variant::kNoPrefix));

TEST_P(KeysetHandlePrefixTest, GenerateNewFromParametersWorks) {
  XChaCha20Poly1305Parameters::Variant variant = GetParam();

  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);

  KeyGenConfiguration config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<
          XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key, config),
      IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, config);
  EXPECT_THAT(handle.status(), IsOk());
  EXPECT_THAT((*handle)->GetPrimary().GetKey()->GetParameters(), Eq(*params));
}

TEST(KeysetHandleGenerateNewFromParametersTest,
     GenerateNewFromParametersEmptyKeyGenConfigFails) {
  Registry::Reset();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);

  KeyGenConfiguration config;
  EXPECT_THAT(
      KeysetHandle::GenerateNewFromParameters<XChaCha20Poly1305Parameters>(
          *params, config)
          .status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(KeysetHandleGenerateNewFromParametersTest,
     GenerateNewFromParametersWithAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};

  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);

  KeyGenConfiguration config;
  ASSERT_THAT(
      internal::KeyGenConfigurationImpl::AddKeyCreator<
          XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key, config),
      IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, config, kAnnotations);
  ASSERT_THAT(handle, IsOk());

  auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(*primitive_wrapper, Wrap(_))
      .WillOnce(
          [&generated_annotations](
              std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
            generated_annotations = generated_primitive_set->get_annotations();
            std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>("");
            return aead;
          });

  // TODO (b/352504713): Remove this once `GetPrimitive` is no longer dependent
  // on the global registry / key managers.
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
              IsOk());
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(
          absl::make_unique<FakeAeadKeyManager>(
              "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"),
          /*new_key_allowed=*/true),
      IsOk());

  EXPECT_THAT(
      (*handle)->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
      IsOk());
  EXPECT_EQ(generated_annotations, kAnnotations);

  // This is needed to cleanup mocks.
  Registry::Reset();
}

TEST(KeysetHandleGenerateNewFromParametersTest,
     GenerateNewFromParametersWithGlobalRegistryConfigFails) {
  Registry::Reset();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);

  EXPECT_THAT(
      KeysetHandle::GenerateNewFromParameters<XChaCha20Poly1305Parameters>(
          *params, KeyGenConfigGlobalRegistry())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeysetHandleTest, GenerateNewWithUnknownPrefixFails) {
  KeyTemplate key_template(AeadKeyTemplates::Aes128Gcm());
  key_template.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, TestKeyGenConfig());
  EXPECT_THAT(handle, StatusIs(absl::StatusCode::kInvalidArgument,
                               HasSubstr("key template has UNKNOWN prefix")));
}

TEST_F(KeysetHandleTest, GenerateNewWithIdRequirementFails) {
  KeyTemplate key_template(AeadKeyTemplates::Aes128Gcm());
  key_template.set_output_prefix_type(OutputPrefixType::WITH_ID_REQUIREMENT);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(key_template, TestKeyGenConfig());
  EXPECT_THAT(
      handle,
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("key template has WITH_ID_REQUIREMENT prefix")));
}

void CompareKeyMetadata(const Keyset::Key& expected,
                        const Keyset::Key& actual) {
  EXPECT_EQ(expected.status(), actual.status());
  EXPECT_EQ(expected.key_id(), actual.key_id());
  EXPECT_EQ(expected.output_prefix_type(), actual.output_prefix_type());
}

absl::StatusOr<const Keyset> CreateEcdsaMultiKeyset() {
  Keyset keyset;
  EcdsaSignKeyManager key_manager;
  EcdsaKeyFormat key_format;

  if (!key_format.ParseFromString(SignatureKeyTemplates::EcdsaP256().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaP256 key template");
  }
  AddTinkKey(EcdsaSignKeyManager().get_key_type(),
             /* key_id= */ 623628, key_manager.CreateKey(key_format).value(),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE, &keyset);

  if (!key_format.ParseFromString(
          SignatureKeyTemplates::EcdsaP384Sha384().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaP384Sha384 key template");
  }
  AddLegacyKey(EcdsaSignKeyManager().get_key_type(),
               /* key_id= */ 36285, key_manager.CreateKey(key_format).value(),
               KeyStatusType::DISABLED, KeyData::ASYMMETRIC_PRIVATE, &keyset);

  if (!key_format.ParseFromString(
          SignatureKeyTemplates::EcdsaP384Sha512().value())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Failed to parse EcdsaP384Sha512 key template");
  }
  AddRawKey(EcdsaSignKeyManager().get_key_type(),
            /* key_id= */ 42, key_manager.CreateKey(key_format).value(),
            KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE, &keyset);
  keyset.set_primary_key_id(42);

  return keyset;
}

// TODO(b/265865177): Modernize existing GetPublicKeysetHandle tests.
TEST_F(KeysetHandleTest, GetPublicKeysetHandle) {
  {  // A keyset with a single key.
    auto handle_result = KeysetHandle::GenerateNew(
        SignatureKeyTemplates::EcdsaP256(), TestKeyGenConfig());
    ASSERT_TRUE(handle_result.ok()) << handle_result.status();
    auto handle = std::move(handle_result.value());
    auto public_handle_result =
        handle->GetPublicKeysetHandle(TestKeyGenConfig());
    ASSERT_TRUE(public_handle_result.ok()) << public_handle_result.status();
    auto keyset = TestKeysetHandle::GetKeyset(*handle);
    auto public_keyset =
        TestKeysetHandle::GetKeyset(*(public_handle_result.value()));
    EXPECT_EQ(keyset.primary_key_id(), public_keyset.primary_key_id());
    EXPECT_EQ(keyset.key_size(), public_keyset.key_size());
    CompareKeyMetadata(keyset.key(0), public_keyset.key(0));
    EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
              public_keyset.key(0).key_data().key_material_type());
  }
  {  // A keyset with multiple keys.
    absl::StatusOr<const Keyset> keyset = CreateEcdsaMultiKeyset();
    ASSERT_THAT(keyset, IsOk());
    std::unique_ptr<KeysetHandle> handle =
        TestKeysetHandle::GetKeysetHandle(*keyset);
    absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
        handle->GetPublicKeysetHandle(TestKeyGenConfig());
    ASSERT_THAT(public_handle, IsOk());
    EXPECT_THAT((*public_handle)->size(), Eq(3));

    const Keyset& public_keyset = TestKeysetHandle::GetKeyset(**public_handle);
    EXPECT_EQ(keyset->primary_key_id(), public_keyset.primary_key_id());
    EXPECT_EQ(keyset->key_size(), public_keyset.key_size());
    for (int i = 0; i < keyset->key_size(); i++) {
      CompareKeyMetadata(keyset->key(i), public_keyset.key(i));
      EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
                public_keyset.key(i).key_data().key_material_type());
    }
  }
}

TEST_F(KeysetHandleTest, GetPublicKeysetHandleErrors) {
  {  // A keyset with a single key.
    auto handle_result = KeysetHandle::GenerateNew(
        AeadKeyTemplates::Aes128Eax(), TestKeyGenConfig());
    ASSERT_TRUE(handle_result.ok()) << handle_result.status();
    auto handle = std::move(handle_result.value());
    auto public_handle_result =
        handle->GetPublicKeysetHandle(TestKeyGenConfig());
    ASSERT_FALSE(public_handle_result.ok());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "ASYMMETRIC_PRIVATE",
                        std::string(public_handle_result.status().message()));
  }
  {  // A keyset with multiple keys.
    Keyset keyset;

    EcdsaKeyFormat ecdsa_key_format;
    ASSERT_TRUE(ecdsa_key_format.ParseFromString(
        SignatureKeyTemplates::EcdsaP256().value()));
    google::crypto::tink::AesGcmKeyFormat aead_key_format;
    aead_key_format.set_key_size(16);
    AddTinkKey(EcdsaSignKeyManager().get_key_type(),
               /* key_id= */ 623628,
               EcdsaSignKeyManager().CreateKey(ecdsa_key_format).value(),
               KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PRIVATE, &keyset);
    AddLegacyKey(AesGcmKeyManager().get_key_type(),
                 /* key_id= */ 42,
                 AesGcmKeyManager().CreateKey(aead_key_format).value(),
                 KeyStatusType::ENABLED,
                 KeyData::ASYMMETRIC_PRIVATE,  // Intentionally wrong setting.
                 &keyset);
    keyset.set_primary_key_id(42);
    auto handle = TestKeysetHandle::GetKeysetHandle(keyset);
    auto public_handle_result =
        handle->GetPublicKeysetHandle(TestKeyGenConfig());
    ASSERT_FALSE(public_handle_result.ok());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "PrivateKeyFactory",
                        std::string(public_handle_result.status().message()));
  }
}

TEST_F(KeysetHandleTest, GetPublicKeysetHandleWithBespokeConfigSucceeds) {
  absl::StatusOr<const Keyset> keyset = CreateEcdsaMultiKeyset();
  ASSERT_THAT(keyset, IsOk());
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(*keyset);

  KeyGenConfiguration config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(), config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(config);
  ASSERT_THAT(public_handle, IsOk());

  const Keyset& public_keyset = TestKeysetHandle::GetKeyset(**public_handle);
  EXPECT_EQ(keyset->primary_key_id(), public_keyset.primary_key_id());
  EXPECT_EQ(keyset->key_size(), public_keyset.key_size());
  for (int i = 0; i < keyset->key_size(); i++) {
    CompareKeyMetadata(keyset->key(i), public_keyset.key(i));
    EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
              public_keyset.key(i).key_data().key_material_type());
  }
}

TEST_F(KeysetHandleTest,
       GetPublicKeysetHandleWithBespokeConfigNoKeyManagersSucceeds) {
  absl::StatusOr<const Keyset> keyset = CreateEcdsaMultiKeyset();
  ASSERT_THAT(keyset, IsOk());
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(*keyset);

  KeyGenConfiguration config;
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(config);
  ASSERT_THAT(public_handle, IsOk());

  const Keyset& public_keyset = TestKeysetHandle::GetKeyset(**public_handle);
  EXPECT_EQ(keyset->primary_key_id(), public_keyset.primary_key_id());
  EXPECT_EQ(keyset->key_size(), public_keyset.key_size());
  for (int i = 0; i < keyset->key_size(); i++) {
    CompareKeyMetadata(keyset->key(i), public_keyset.key(i));
    EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
              public_keyset.key(i).key_data().key_material_type());
  }
}

TEST_F(
    KeysetHandleTest,
    GetPublicKeysetHandleWithBespokeConfigEmptySerializationRegistryFails) {
  internal::MutableSerializationRegistry::GlobalInstance().Reset();
  absl::StatusOr<const Keyset> keyset = CreateEcdsaMultiKeyset();
  ASSERT_THAT(keyset, IsOk());
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(*keyset);

  KeyGenConfiguration config;
  EXPECT_THAT(handle->GetPublicKeysetHandle(config).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeysetHandleTest, GetPublicKeysetHandleWithBespokeConfigFails) {
  KeyGenConfiguration config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), config);
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT((*handle)->GetPublicKeysetHandle(config).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(KeysetHandleTest,
       GetPublicKeysetHandleWithGlobalRegistryConfigSucceeds) {
  absl::StatusOr<const Keyset> keyset = CreateEcdsaMultiKeyset();
  ASSERT_THAT(keyset, IsOk());
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(*keyset);

  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());

  const Keyset& public_keyset = TestKeysetHandle::GetKeyset(**public_handle);
  EXPECT_EQ(keyset->primary_key_id(), public_keyset.primary_key_id());
  EXPECT_EQ(keyset->key_size(), public_keyset.key_size());
  for (int i = 0; i < keyset->key_size(); i++) {
    CompareKeyMetadata(keyset->key(i), public_keyset.key(i));
    EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC,
              public_keyset.key(i).key_data().key_material_type());
  }
}

TEST_F(KeysetHandleTest, GetPublicKeysetHandleWithGlobalRegistryConfigFails) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(
      (*handle)->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry()).status(),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(KeysetHandleTest, GetPrimitive) {
  Keyset keyset;
  KeyData key_data_0 =
      *Registry::NewKeyData(AeadKeyTemplates::Aes128Gcm()).value();
  AddKeyData(key_data_0, /*key_id=*/0,
             google::crypto::tink::OutputPrefixType::TINK,
             KeyStatusType::ENABLED, &keyset);
  KeyData key_data_1 =
      *Registry::NewKeyData(AeadKeyTemplates::Aes256Gcm()).value();
  AddKeyData(key_data_1, /*key_id=*/1,
             google::crypto::tink::OutputPrefixType::TINK,
             KeyStatusType::ENABLED, &keyset);
  KeyData key_data_2 =
      *Registry::NewKeyData(AeadKeyTemplates::Aes256Gcm()).value();
  AddKeyData(key_data_2, /*key_id=*/2,
             google::crypto::tink::OutputPrefixType::RAW,
             KeyStatusType::ENABLED, &keyset);
  keyset.set_primary_key_id(1);
  std::unique_ptr<KeysetHandle> keyset_handle =
      TestKeysetHandle::GetKeysetHandle(keyset);

  // Check that encryption with the primary can be decrypted with key_data_1.
  auto aead_result =
      keyset_handle->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry());
  ASSERT_TRUE(aead_result.ok()) << aead_result.status();
  std::unique_ptr<Aead> aead = std::move(aead_result.value());

  std::string plaintext = "plaintext";
  std::string aad = "aad";
  std::string encryption = aead->Encrypt(plaintext, aad).value();
  EXPECT_EQ(aead->Decrypt(encryption, aad).value(), plaintext);

  std::unique_ptr<Aead> raw_aead =
      Registry::GetPrimitive<Aead>(key_data_2).value();
  EXPECT_FALSE(raw_aead->Decrypt(encryption, aad).ok());

  std::string raw_encryption = raw_aead->Encrypt(plaintext, aad).value();
  EXPECT_EQ(aead->Decrypt(raw_encryption, aad).value(), plaintext);
}

TEST_F(KeysetHandleTest, GetPrimitiveWithBespokeConfigSucceeds) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), key_gen_config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  Configuration config;
  ASSERT_THAT(internal::ConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), config),
              IsOk());
  ASSERT_THAT(internal::ConfigurationImpl::AddPrimitiveWrapper(
                  absl::make_unique<AeadWrapper>(), config),
              IsOk());

  EXPECT_THAT((*handle)->GetPrimitive<Aead>(config).status(), IsOk());
}

TEST_F(KeysetHandleTest, GetPrimitiveWithBespokeConfigFailsIfEmpty) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), key_gen_config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(), key_gen_config);
  ASSERT_THAT(handle, IsOk());

  Configuration config;
  EXPECT_THAT((*handle)->GetPrimitive<Aead>(config).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeysetHandleTest, GetPrimitiveWithGlobalRegistryConfig) {
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());

  EXPECT_THAT((*handle)->GetPrimitive<Aead>(ConfigGlobalRegistry()), IsOk());
}

TEST_P(KeysetHandlePrefixTest,
       GetPrimitiveWithBespokeConfigUsingPrimitiveGettersSucceeds) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  Registry::Reset();
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  XChaCha20Poly1305Parameters::Variant variant = GetParam();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(variant);
  ASSERT_THAT(params, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, key_gen_config);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT((*handle)->Validate(), IsOk());
  EXPECT_THAT((*handle)->GetPrimary().GetKey()->GetParameters(), Eq(*params));

  Configuration config;
  ASSERT_THAT(
      (internal::ConfigurationImpl::AddPrimitiveGetter<Aead,
                                                       XChaCha20Poly1305Key>(
          GetPrimitiveForXChaCha20Poly1305Key, config)),
      IsOk());
  ASSERT_THAT(internal::ConfigurationImpl::AddPrimitiveWrapper(
                  absl::make_unique<AeadWrapper>(), config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      (*handle)->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  const std::string plaintext = "plaintext";
  const std::string aad = "aad";
  absl::StatusOr<std::string> encryption = (*aead)->Encrypt(plaintext, aad);
  ASSERT_THAT(encryption, IsOk());
  absl::StatusOr<std::string> decryption = (*aead)->Decrypt(*encryption, aad);
  ASSERT_THAT(decryption, IsOk());
  EXPECT_EQ(*decryption, plaintext);
}

TEST_F(KeysetHandleTest,
       GetPrimitiveWithBespokeConfigUsingMultipleKeysPrimitiveGettersSucceeds) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  Registry::Reset();
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(params, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*params,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/true);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *params, KeyStatus::kEnabled, /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(2));

  ASSERT_THAT(handle->Validate(), IsOk());
  EXPECT_THAT(handle->GetPrimary().GetKey()->GetParameters(), Eq(*params));

  KeysetHandle::Entry expected_entry1 = (*handle)[1];
  EXPECT_THAT(expected_entry1.IsPrimary(), IsFalse());
  EXPECT_THAT(expected_entry1.GetKey()->GetParameters(), Eq(*params));

  Configuration config;
  ASSERT_THAT(
      (internal::ConfigurationImpl::AddPrimitiveGetter<Aead,
                                                       XChaCha20Poly1305Key>(
          GetPrimitiveForXChaCha20Poly1305Key, config)),
      IsOk());
  ASSERT_THAT(internal::ConfigurationImpl::AddPrimitiveWrapper(
                  absl::make_unique<AeadWrapper>(), config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      handle->GetPrimitive<Aead>(config);
  ASSERT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  const std::string plaintext = "plaintext";
  const std::string aad = "aad";
  absl::StatusOr<std::string> encryption = (*aead)->Encrypt(plaintext, aad);
  ASSERT_THAT(encryption, IsOk());
  absl::StatusOr<std::string> decryption = (*aead)->Decrypt(*encryption, aad);
  ASSERT_THAT(decryption, IsOk());
  EXPECT_EQ(*decryption, plaintext);
}

TEST_F(KeysetHandleTest,
       GetPrimitiveWithBespokeConfigMultipleKeysMixedPrimitiveGettersSucceeds) {
  if (!internal::IsBoringSsl()) {
    GTEST_SKIP() << "XChaCha20-Poly1305 is not supported when OpenSSL is used";
  }
  Registry::Reset();
  ASSERT_THAT(AeadConfig::Register(), IsOk());
  absl::StatusOr<XChaCha20Poly1305Parameters> xchacha_params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);
  ASSERT_THAT(xchacha_params, IsOk());

  absl::StatusOr<AesGcmParameters> aes_gcm_params =
      AesGcmParameters::Builder()
          .SetKeySizeInBytes(16)
          .SetIvSizeInBytes(12)
          .SetTagSizeInBytes(16)
          .SetVariant(AesGcmParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(aes_gcm_params, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), key_gen_config),
              IsOk());

  KeysetHandleBuilder::Entry entry0 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(*xchacha_params,
                                                           KeyStatus::kEnabled,
                                                           /*is_primary=*/true);

  KeysetHandleBuilder::Entry entry1 =
      KeysetHandleBuilder::Entry::CreateFromCopyableParams(
          *aes_gcm_params, KeyStatus::kEnabled, /*is_primary=*/false);

  absl::StatusOr<KeysetHandle> handle = KeysetHandleBuilder()
                                            .AddEntry(std::move(entry0))
                                            .AddEntry(std::move(entry1))
                                            .Build(key_gen_config);
  ASSERT_THAT(handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(2));

  ASSERT_THAT(handle->Validate(), IsOk());
  EXPECT_THAT(handle->GetPrimary().GetKey()->GetParameters(),
              Eq(*xchacha_params));

  KeysetHandle::Entry expected_entry1 = (*handle)[1];
  EXPECT_THAT(expected_entry1.IsPrimary(), IsFalse());
  EXPECT_THAT(expected_entry1.GetKey()->GetParameters(), Eq(*aes_gcm_params));

  Configuration config;
  ASSERT_THAT(
      (internal::ConfigurationImpl::AddPrimitiveGetter<Aead,
                                                       XChaCha20Poly1305Key>(
          GetPrimitiveForXChaCha20Poly1305Key, config)),
      IsOk());
  ASSERT_THAT(internal::ConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), config),
              IsOk());
  ASSERT_THAT(internal::ConfigurationImpl::AddPrimitiveWrapper(
                  absl::make_unique<AeadWrapper>(), config),
              IsOk());

  absl::StatusOr<std::unique_ptr<Aead>> aead =
      handle->GetPrimitive<Aead>(config);
  EXPECT_THAT(aead, IsOk());

  // Check that encrypt/decrypt works.
  const std::string plaintext = "plaintext";
  const std::string aad = "aad";
  absl::StatusOr<std::string> encryption = (*aead)->Encrypt(plaintext, aad);
  ASSERT_THAT(encryption, IsOk());
  absl::StatusOr<std::string> decryption = (*aead)->Decrypt(*encryption, aad);
  ASSERT_THAT(decryption, IsOk());
  EXPECT_EQ(*decryption, plaintext);
}

TEST_F(KeysetHandleTest, GetPrimitiveWithBespokeConfigNoPrimitiveGetterFails) {
  Registry::Reset();
  absl::StatusOr<XChaCha20Poly1305Parameters> params =
      XChaCha20Poly1305Parameters::Create(
          XChaCha20Poly1305Parameters::Variant::kNoPrefix);

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(internal::KeyGenConfigurationImpl::AddKeyCreator<
                  XChaCha20Poly1305Parameters>(CreateXChaCha20Poly1305Key,
                                               key_gen_config),
              IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNewFromParameters(*params, key_gen_config);
  EXPECT_THAT(handle, IsOk());
  EXPECT_THAT((*handle)->GetPrimary().GetKey()->GetParameters(), Eq(*params));

  Configuration config;
  ASSERT_THAT(internal::ConfigurationImpl::AddPrimitiveWrapper(
                  absl::make_unique<AeadWrapper>(), config),
              IsOk());

  EXPECT_THAT((*handle)->GetPrimitive<Aead>(config).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST_F(KeysetHandleTest, GetPrimitiveWithConfigFips1402) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                KeyGenConfigFips140_2());
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT((*handle)->GetPrimitive<Aead>(ConfigFips140_2()), IsOk());
}

TEST_F(KeysetHandleTest, GetPrimitiveWithConfigFips1402FailsWithNonFipsHandle) {
  if (!internal::IsFipsEnabledInSsl()) {
    GTEST_SKIP() << "Only test in FIPS mode";
  }

  Keyset keyset;
  AesGcmSivKeyProto key_proto;
  key_proto.set_key_value(subtle::Random::GetRandomBytes(16));
  test::AddTinkKey(AeadKeyTemplates::Aes256GcmSiv().type_url(), /*key_id=*/13,
                   key_proto, KeyStatusType::ENABLED, KeyData::SYMMETRIC,
                   &keyset);
  keyset.set_primary_key_id(13);

  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  EXPECT_THAT(handle->GetPrimitive<Aead>(ConfigFips140_2()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

// Tests that GetPrimitive(nullptr) fails with a non-ok status.
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST_F(KeysetHandleTest, GetPrimitiveNullptrKeyManager) {
  Keyset keyset;
  AddKeyData(*Registry::NewKeyData(AeadKeyTemplates::Aes128Gcm()).value(),
             /*key_id=*/0, google::crypto::tink::OutputPrefixType::TINK,
             KeyStatusType::ENABLED, &keyset);
  keyset.set_primary_key_id(0);
  std::unique_ptr<KeysetHandle> keyset_handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(keyset_handle->GetPrimitive<Aead>(nullptr).status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END

// Test creating with custom key manager. For this, we reset the registry before
// asking for the primitive.
// NOLINTBEGIN(whitespace/line_length) (Formatted when commented in)
// TINK-PENDING-REMOVAL-IN-3.0.0-START
TEST_F(KeysetHandleTest, GetPrimitiveCustomKeyManager) {
  auto handle_result =
  KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Gcm(),
                                                 KeyGenConfigGlobalRegistry());
  ASSERT_TRUE(handle_result.ok()) << handle_result.status();
  std::unique_ptr<KeysetHandle> handle = std::move(handle_result.value());
  Registry::Reset();
  ASSERT_TRUE(
      Registry::RegisterPrimitiveWrapper(absl::make_unique<AeadWrapper>())
          .ok());
  // Without custom key manager it now fails.
  ASSERT_FALSE(
      handle->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()).ok());
  AesGcmKeyManager key_type_manager;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      crypto::tink::internal::MakeKeyManager<Aead>(&key_type_manager);
  // With custom key manager it works ok.
  ASSERT_TRUE(handle->GetPrimitive<Aead>(key_manager.get()).ok());
}
// TINK-PENDING-REMOVAL-IN-3.0.0-END
// NOLINTEND(whitespace/line_length)

// Compile time check: ensures that the KeysetHandle can be copied.
TEST_F(KeysetHandleTest, Copiable) {
  auto handle_result = KeysetHandle::GenerateNew(AeadKeyTemplates::Aes128Eax(),
                                                 TestKeyGenConfig());
  ASSERT_TRUE(handle_result.ok()) << handle_result.status();
  std::unique_ptr<KeysetHandle> handle = std::move(handle_result.value());
  KeysetHandle handle_copy = *handle;
}

TEST_F(KeysetHandleTest, ReadNoSecret) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::REMOTE, &keyset);
  keyset.set_primary_key_id(42);
  auto handle_result = KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
  ASSERT_THAT(handle_result, IsOk());
  std::unique_ptr<KeysetHandle>& keyset_handle = handle_result.value();

  const Keyset& result = CleartextKeysetHandle::GetKeyset(*keyset_handle);
  // We check that result equals keyset. For lack of a better method we do this
  // by hand.
  EXPECT_EQ(result.primary_key_id(), keyset.primary_key_id());
  ASSERT_EQ(result.key_size(), keyset.key_size());
  ASSERT_EQ(result.key(0).key_id(), keyset.key(0).key_id());
  ASSERT_EQ(result.key(1).key_id(), keyset.key(1).key_id());
}

TEST_F(KeysetHandleTest, ReadNoSecretWithAnnotations) {
  const absl::flat_hash_map<std::string, std::string> kAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};
  Keyset keyset = GetPublicTestKeyset();
  absl::StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      KeysetHandle::ReadNoSecret(keyset.SerializeAsString(), kAnnotations);
  ASSERT_THAT(keyset_handle, IsOk());
  auto primitive_wrapper = absl::make_unique<MockAeadPrimitiveWrapper>();
  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(*primitive_wrapper, Wrap(_))
      .WillOnce(
          [&generated_annotations](
              std::unique_ptr<PrimitiveSet<Aead>> generated_primitive_set) {
            generated_annotations = generated_primitive_set->get_annotations();
            std::unique_ptr<Aead> aead = absl::make_unique<DummyAead>("");
            return aead;
          });
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(std::move(primitive_wrapper)),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<FakeAeadKeyManager>("some_other_key_type"),
                  /*new_key_allowed=*/true),
              IsOk());

  EXPECT_THAT((*keyset_handle)
                  ->GetPrimitive<crypto::tink::Aead>(ConfigGlobalRegistry()),
              IsOk());
  EXPECT_EQ(generated_annotations, kAnnotations);
  // This is needed to cleanup mocks.
  Registry::Reset();
}

TEST_F(KeysetHandleTest, ReadNoSecretFailForTypeUnknown) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::UNKNOWN_KEYMATERIAL, &keyset);
  keyset.set_primary_key_id(42);
  auto result = KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleTest, ReadNoSecretFailForTypeSymmetric) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);
  auto result = KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleTest, ReadNoSecretFailForTypeAssymmetricPrivate) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PRIVATE, &keyset);
  keyset.set_primary_key_id(42);
  auto result = KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleTest, ReadNoSecretFailForHidden) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  AddRawKey("some_other_key_type", 10, key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i + 100, key,
              KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }

  keyset.set_primary_key_id(42);
  auto result = KeysetHandle::ReadNoSecret(keyset.SerializeAsString());
  EXPECT_THAT(result.status(), StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(KeysetHandleTest, ReadNoSecretFailForInvalidString) {
  auto result = KeysetHandle::ReadNoSecret("bad serialized keyset");
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
}

TEST_F(KeysetHandleTest, WriteNoSecret) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  AddRawKey("some_other_key_type", 711, key, KeyStatusType::ENABLED,
            KeyData::REMOTE, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();
  auto result = handle->WriteNoSecret(writer.get());
  EXPECT_TRUE(result.ok());
}

TEST_F(KeysetHandleTest, WriteNoSecretFailForTypeUnknown) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::UNKNOWN_KEYMATERIAL, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();
  auto result = handle->WriteNoSecret(writer.get());
  EXPECT_FALSE(result.ok());
}

TEST_F(KeysetHandleTest, WriteNoSecretFailForTypeSymmetric) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();
  auto result = handle->WriteNoSecret(writer.get());
  EXPECT_FALSE(result.ok());
}

TEST_F(KeysetHandleTest, WriteNoSecretFailForTypeAssymmetricPrivate) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PRIVATE, &keyset);
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();
  auto result = handle->WriteNoSecret(writer.get());
  EXPECT_FALSE(result.ok());
}

TEST_F(KeysetHandleTest, WriteNoSecretFailForHidden) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  AddRawKey("some_other_key_type", 10, key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i + 100, key,
              KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }

  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);

  std::stringbuf buffer;
  auto destination_stream = std::make_unique<std::ostream>(&buffer);
  auto writer =
      test::DummyKeysetWriter::New(std::move(destination_stream)).value();
  auto result = handle->WriteNoSecret(writer.get());
  EXPECT_FALSE(result.ok());
}

TEST_F(KeysetHandleTest, GetKeysetInfo) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  AddRawKey("some_other_key_type", 10, key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i + 100, key,
              KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  keyset.set_primary_key_id(42);

  auto handle = TestKeysetHandle::GetKeysetHandle(keyset);
  auto keyset_info = handle->GetKeysetInfo();

  EXPECT_EQ(keyset.primary_key_id(), keyset_info.primary_key_id());
  for (int i = 0; i < keyset.key_size(); ++i) {
    auto key_info = keyset_info.key_info(i);
    auto key = keyset.key(i);
    EXPECT_EQ(key.key_data().type_url(), key_info.type_url());
    EXPECT_EQ(key.status(), key_info.status());
    EXPECT_EQ(key.key_id(), key_info.key_id());
    EXPECT_EQ(key.output_prefix_type(), key_info.output_prefix_type());
  }
}

TEST_F(KeysetHandleTest, GetEntryFromSingleKeyKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(11);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(*handle, SizeIs(1));

  ASSERT_THAT(handle->ValidateAt(0), IsOk());
  KeysetHandle::Entry entry = (*handle)[0];

  EXPECT_THAT(entry.GetId(), Eq(11));
  EXPECT_THAT(entry.GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT(entry.IsPrimary(), IsTrue());
  EXPECT_THAT(entry.GetKey()->GetIdRequirement(), Eq(11));
  EXPECT_THAT(entry.GetKey()->GetParameters().HasIdRequirement(), IsTrue());
}

TEST_F(KeysetHandleTest, GetEntryFromMultipleKeyKeyset) {
  Keyset keyset;
  Keyset::Key key;
  AddRawKey("first_key_type", 11, key, KeyStatusType::DISABLED,
            KeyData::SYMMETRIC, &keyset);
  AddTinkKey("second_key_type", 22, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddRawKey("third_key_type", 33, key, KeyStatusType::DESTROYED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(22);

  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(*handle, SizeIs(3));

  ASSERT_THAT(handle->ValidateAt(0), IsOk());
  KeysetHandle::Entry entry0 = (*handle)[0];
  EXPECT_THAT(entry0.GetId(), Eq(11));
  EXPECT_THAT(entry0.GetStatus(), Eq(KeyStatus::kDisabled));
  EXPECT_THAT(entry0.IsPrimary(), IsFalse());
  EXPECT_THAT(entry0.GetKey()->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(entry0.GetKey()->GetParameters().HasIdRequirement(), IsFalse());

  ASSERT_THAT(handle->ValidateAt(1), IsOk());
  KeysetHandle::Entry entry1 = (*handle)[1];
  EXPECT_THAT(entry1.GetId(), Eq(22));
  EXPECT_THAT(entry1.GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT(entry1.IsPrimary(), IsTrue());
  EXPECT_THAT(entry1.GetKey()->GetIdRequirement(), Eq(22));
  EXPECT_THAT(entry1.GetKey()->GetParameters().HasIdRequirement(), IsTrue());

  ASSERT_THAT(handle->ValidateAt(2), IsOk());
  KeysetHandle::Entry entry2 = (*handle)[2];
  EXPECT_THAT(entry2.GetId(), Eq(33));
  EXPECT_THAT(entry2.GetStatus(), Eq(KeyStatus::kDestroyed));
  EXPECT_THAT(entry2.IsPrimary(), IsFalse());
  EXPECT_THAT(entry2.GetKey()->GetIdRequirement(), Eq(absl::nullopt));
  EXPECT_THAT(entry2.GetKey()->GetParameters().HasIdRequirement(), IsFalse());
}

TEST_F(KeysetHandleTest, IdenticalEntriesAreEqual) {
  RestrictedData key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  KeysetHandleBuilder::Entry builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(builder_entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(handle->Validate(), IsOk());

  KeysetHandleBuilder::Entry other_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  other_builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> other_handle =
      KeysetHandleBuilder().AddEntry(std::move(other_builder_entry)).Build();
  ASSERT_THAT(other_handle.status(), IsOk());
  ASSERT_THAT(other_handle->Validate(), IsOk());

  EXPECT_THAT((*handle)[0] == (*other_handle)[0], IsTrue());
  EXPECT_THAT((*handle)[0] != (*other_handle)[0], IsFalse());
}

TEST_F(KeysetHandleTest, EntriesWithDifferentKeysAreNotEqual) {
  RestrictedData key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  RestrictedData other_key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> other_key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, other_key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(other_key, IsOk());

  KeysetHandleBuilder::Entry builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(builder_entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(handle->Validate(), IsOk());

  KeysetHandleBuilder::Entry other_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *other_key, KeyStatus::kEnabled, /*is_primary=*/true);
  other_builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> other_handle =
      KeysetHandleBuilder().AddEntry(std::move(other_builder_entry)).Build();
  ASSERT_THAT(other_handle.status(), IsOk());
  ASSERT_THAT(other_handle->Validate(), IsOk());

  EXPECT_THAT((*handle)[0] != (*other_handle)[0], IsTrue());
  EXPECT_THAT((*handle)[0] == (*other_handle)[0], IsFalse());
}

TEST_F(KeysetHandleTest, EntriesWithDifferentIdsAreNotEqual) {
  RestrictedData key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  KeysetHandleBuilder::Entry builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(builder_entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(handle->Validate(), IsOk());

  KeysetHandleBuilder::Entry other_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  other_builder_entry.SetFixedId(456);
  absl::StatusOr<KeysetHandle> other_handle =
      KeysetHandleBuilder().AddEntry(std::move(other_builder_entry)).Build();
  ASSERT_THAT(other_handle.status(), IsOk());
  ASSERT_THAT(other_handle->Validate(), IsOk());

  EXPECT_THAT((*handle)[0] != (*other_handle)[0], IsTrue());
  EXPECT_THAT((*handle)[0] == (*other_handle)[0], IsFalse());
}

TEST_F(KeysetHandleTest, EntriesWithDifferentStatusesAreNotEqual) {
  RestrictedData key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  KeysetHandleBuilder::Entry primary_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  primary_builder_entry.SetFixedId(123);
  KeysetHandleBuilder::Entry builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/false);
  builder_entry.SetFixedId(456);
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(std::move(primary_builder_entry))
          .AddEntry(std::move(builder_entry))
          .Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(handle->Validate(), IsOk());

  KeysetHandleBuilder::Entry other_primary_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  other_primary_builder_entry.SetFixedId(123);
  // Primary keys must be enabled, so we need to compare non-primary keys.
  KeysetHandleBuilder::Entry other_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kDisabled, /*is_primary=*/false);
  other_builder_entry.SetFixedId(456);
  absl::StatusOr<KeysetHandle> other_handle =
      KeysetHandleBuilder()
          .AddEntry(std::move(other_primary_builder_entry))
          .AddEntry(std::move(other_builder_entry))
          .Build();
  ASSERT_THAT(other_handle.status(), IsOk());
  ASSERT_THAT(other_handle->Validate(), IsOk());

  EXPECT_THAT((*handle)[1] != (*other_handle)[1], IsTrue());
  EXPECT_THAT((*handle)[1] == (*other_handle)[1], IsFalse());
}

TEST_F(KeysetHandleTest, PrimaryAndNonPrimaryEntriesAreNotEqual) {
  RestrictedData key_bytes(32);
  absl::StatusOr<XChaCha20Poly1305Key> key = XChaCha20Poly1305Key::Create(
      XChaCha20Poly1305Parameters::Variant::kNoPrefix, key_bytes,
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  ASSERT_THAT(key, IsOk());

  KeysetHandleBuilder::Entry builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  builder_entry.SetFixedId(123);
  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(builder_entry)).Build();
  ASSERT_THAT(handle.status(), IsOk());
  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT((*handle)[0].IsPrimary(), IsTrue());

  KeysetHandleBuilder::Entry other_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/false);
  other_builder_entry.SetFixedId(123);
  // Need primary entry for the keyset to build.
  KeysetHandleBuilder::Entry primary_builder_entry =
      KeysetHandleBuilder::Entry::CreateFromCopyableKey(
          *key, KeyStatus::kEnabled, /*is_primary=*/true);
  primary_builder_entry.SetFixedId(456);
  absl::StatusOr<KeysetHandle> other_handle =
      KeysetHandleBuilder()
          .AddEntry(std::move(primary_builder_entry))
          .AddEntry(std::move(other_builder_entry))
          .Build();
  ASSERT_THAT(other_handle.status(), IsOk());
  ASSERT_THAT(other_handle->Validate(), IsOk());
  ASSERT_THAT((*other_handle)[1].IsPrimary(), IsFalse());

  EXPECT_THAT((*handle)[0] != (*other_handle)[1], IsTrue());
  EXPECT_THAT((*handle)[0] == (*other_handle)[1], IsFalse());
}

TEST_F(KeysetHandleDeathTest, EntryWithIndexOutOfBoundsCrashes) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(11);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_DEATH_IF_SUPPORTED((*handle)[-1],
                            "Invalid index -1 for keyset of size 1");
  EXPECT_DEATH_IF_SUPPORTED((*handle)[1],
                            "Invalid index 1 for keyset of size 1");
}

TEST_F(KeysetHandleDeathTest, EntryWithUnknownStatusFails) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::UNKNOWN_STATUS,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(11);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_THAT(handle->Validate(), StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(handle->ValidateAt(0),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_DEATH_IF_SUPPORTED((*handle)[0], "Invalid key status type.");
}

TEST_F(KeysetHandleDeathTest, EntryWithUnprintableTypeUrlFails) {
  Keyset keyset;
  Keyset::Key key;
  AddRawKey("invalid key type url with spaces", 11, key, KeyStatusType::ENABLED,
            KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(11);

  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_THAT(handle->Validate(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(handle->ValidateAt(0),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_DEATH_IF_SUPPORTED((*handle)[0],
                            "Non-printable ASCII character in type URL.");
}

TEST_F(KeysetHandleTest, GetPrimary) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddTinkKey("first_key_type", 22, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddTinkKey("first_key_type", 33, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(33);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(*handle, SizeIs(3));

  absl::StatusOr<KeysetHandle::Entry> primary = handle->GetPrimary();
  ASSERT_THAT(primary, IsOk());

  EXPECT_THAT(primary->GetId(), Eq(33));
  EXPECT_THAT(primary->GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT(primary->IsPrimary(), IsTrue());
}

TEST_F(KeysetHandleDeathTest, NonexistentPrimaryFails) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_THAT(handle->Validate(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_DEATH_IF_SUPPORTED(handle->GetPrimary(), "Keyset has no primary");
}

TEST_F(KeysetHandleDeathTest, MultiplePrimariesFail) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  AddTinkKey("second_key_type", 11, key, KeyStatusType::ENABLED,
             KeyData::SYMMETRIC, &keyset);
  // Multiple primaries since two distinct keys share the same key id.
  keyset.set_primary_key_id(11);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(*handle, SizeIs(2));

  EXPECT_THAT(handle->Validate(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_DEATH_IF_SUPPORTED(handle->GetPrimary(),
                            "Keyset has more than one primary");
}

TEST_F(KeysetHandleDeathTest, GetDisabledPrimaryFails) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("first_key_type", 11, key, KeyStatusType::DISABLED,
             KeyData::SYMMETRIC, &keyset);
  keyset.set_primary_key_id(11);
  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  ASSERT_THAT(*handle, SizeIs(1));

  EXPECT_THAT(handle->Validate(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_DEATH_IF_SUPPORTED(handle->GetPrimary(),
                            "Keyset has primary that is not enabled");
}

}  // namespace
}  // namespace tink
}  // namespace crypto
