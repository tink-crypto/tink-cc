// Copyright 2022 Google LLC
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

#include "tink/proto_keyset_format.h"

#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/internal/testing/test_only_key_managers.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::internal::CreateTestOnlyKey;
using ::crypto::tink::internal::KeyGenConfigurationImpl;
using ::crypto::tink::internal::RegisterTestOnlyProtoSerialization;
using ::crypto::tink::internal::TestOnlyParameters;
using ::crypto::tink::internal::TestOnlyPrivateKeyTemplate;
using ::crypto::tink::internal::TestOnlyPrivateKeyTypeManager;
using ::crypto::tink::internal::TestOnlyPublicKeyTypeManager;
using ::crypto::tink::internal::TestOnlySymmetricKey;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::util::SecretDataAsStringView;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::SizeIs;

class SerializeKeysetToProtoKeysetFormatTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_THAT(RegisterTestOnlyProtoSerialization(), IsOk());
    ASSERT_THAT(KeyGenConfigurationImpl::AddKeyCreator<TestOnlyParameters>(
                    CreateTestOnlyKey, key_gen_config_),
                IsOk());
  }

  KeyGenConfiguration key_gen_config_;
};

absl::StatusOr<TestOnlyParameters> NoPrefixParameters() {
  return TestOnlyParameters::Create(TestOnlyParameters::Variant::kNoPrefix);
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseSingleKey) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization = SerializeKeysetToProtoKeysetFormat(
      *handle, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
      SecretDataAsStringView(*serialization), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(1));
  ASSERT_THAT(*parsed_handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseMultipleKeys) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
              /*id=*/123))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/125))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kDisabled, /*is_primary=*/false,
              /*id=*/127))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization = SerializeKeysetToProtoKeysetFormat(
      *handle, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
      SecretDataAsStringView(*serialization), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(3));
  ASSERT_THAT(*parsed_handle, SizeIs(3));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
  EXPECT_THAT((*handle)[1], Eq((*parsed_handle)[1]));
  EXPECT_THAT((*handle)[2], Eq((*parsed_handle)[2]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeNoAccessFails) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::string> serialization =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(*handle);
  ASSERT_THAT(serialization, Not(IsOk()));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, ParseNoAccessFails) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization = SerializeKeysetToProtoKeysetFormat(
      *handle, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization));
  ASSERT_THAT(parsed_handle, Not(IsOk()));
}

// Serialized keyset with a single enabled primary test-only key with TINK
// output prefix, ID 0x01020304 and key bytes 000102...0f. It is the binary
// serialization of the `Keyset` proto
//   primary_key_id: 0x01020304
//   key {
//     key_data {
//       type_url: "type.googleapis.com/google.crypto.tink.TestOnlyKey"
//       value: <serialized `TestOnlyKey` with version 0 and key_value
//               000102...0f>
//       key_material_type: SYMMETRIC
//     }
//     status: ENABLED
//     key_id: 0x01020304
//     output_prefix_type: TINK
//   }
constexpr absl::string_view kHexSerializedTestVectorKeyset =
    "088486880812550a4a0a32747970652e676f6f676c65617069732e636f6d2f676f6f676c"
    "652e63727970746f2e74696e6b2e546573744f6e6c794b65791212121000010203040506"
    "0708090a0b0c0d0e0f1801100118848688082001";

// Returns the key of `kHexSerializedTestVectorKeyset`.
absl::StatusOr<TestOnlySymmetricKey> TestVectorKey() {
  absl::StatusOr<TestOnlyParameters> parameters =
      TestOnlyParameters::Create(TestOnlyParameters::Variant::kTink);
  if (!parameters.ok()) {
    return parameters.status();
  }
  return TestOnlySymmetricKey::Create(
      *parameters,
      RestrictedData(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"),
                     InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/0x01020304, GetPartialKeyAccess());
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, TestVector) {
  std::string serialized_keyset =
      test::HexDecodeOrDie(kHexSerializedTestVectorKeyset);
  absl::StatusOr<KeysetHandle> keyset_handle = ParseKeysetFromProtoKeysetFormat(
      serialized_keyset, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  ASSERT_THAT(*keyset_handle, SizeIs(1));

  absl::StatusOr<TestOnlySymmetricKey> expected_key = TestVectorKey();
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT((*keyset_handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*keyset_handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*keyset_handle)[0].GetId(), Eq(0x01020304));
  EXPECT_THAT(*(*keyset_handle)[0].GetKey(), Eq(*expected_key));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParsePublicKey) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(
      KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
          std::make_unique<TestOnlyPrivateKeyTypeManager>(),
          std::make_unique<TestOnlyPublicKeyTypeManager>(), key_gen_config),
      IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(
          TestOnlyPrivateKeyTemplate(OutputPrefixType::RAW), key_gen_config);
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      (*handle)->GetPublicKeysetHandle(key_gen_config);
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<SecretData> serialization1 =
      SerializeKeysetToProtoKeysetFormat(**public_handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  absl::StatusOr<std::string> serialization2 =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(**public_handle);
  ASSERT_THAT(serialization2, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle1 =
      ParseKeysetFromProtoKeysetFormat(SecretDataAsStringView(*serialization1),
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle1, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle2 =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization1));
  ASSERT_THAT(parsed_handle2, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle3 =
      ParseKeysetFromProtoKeysetFormat(*serialization2,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle3, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle4 =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(*serialization2);
  ASSERT_THAT(parsed_handle4, IsOk());

  ASSERT_THAT(**public_handle, SizeIs(1));
  ASSERT_THAT(*parsed_handle1, SizeIs(1));
  ASSERT_THAT(*parsed_handle2, SizeIs(1));
  ASSERT_THAT(*parsed_handle3, SizeIs(1));
  ASSERT_THAT(*parsed_handle4, SizeIs(1));

  ASSERT_THAT((*public_handle)->Validate(), IsOk());
  ASSERT_THAT(parsed_handle1->Validate(), IsOk());
  ASSERT_THAT(parsed_handle2->Validate(), IsOk());
  ASSERT_THAT(parsed_handle3->Validate(), IsOk());
  ASSERT_THAT(parsed_handle4->Validate(), IsOk());
  EXPECT_THAT((**public_handle)[0], Eq((*parsed_handle1)[0]));
  EXPECT_THAT((**public_handle)[0], Eq((*parsed_handle2)[0]));
  EXPECT_THAT((**public_handle)[0], Eq((*parsed_handle3)[0]));
  EXPECT_THAT((**public_handle)[0], Eq((*parsed_handle4)[0]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest,
       SerializeAndParseSingleEncryptedKey) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  DummyAead aead("keyset encryption aead");

  absl::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, aead, "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(*encrypted_keyset, aead,
                                           "associated_data");
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(1));
  ASSERT_THAT(*parsed_handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest,
       SerializeAndParseMultipleEncryptedKeys) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/false,
              /*id=*/123))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/125))
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kDisabled, /*is_primary=*/false,
              /*id=*/127))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  DummyAead aead("keyset encryption aead");

  absl::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, aead, "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(*encrypted_keyset, aead,
                                           "associated_data");
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(3));
  ASSERT_THAT(*parsed_handle, SizeIs(3));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
  EXPECT_THAT((*handle)[1], Eq((*parsed_handle)[1]));
  EXPECT_THAT((*handle)[2], Eq((*parsed_handle)[2]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest,
       SerializedEncryptedKeysetCanBeReadByKeysetHandle) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  DummyAead aead("keyset encryption aead");

  absl::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, aead, "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(*encrypted_keyset);
  ASSERT_THAT(reader, IsOk());

  absl::StatusOr<std::unique_ptr<KeysetHandle>> parsed_handle =
      KeysetHandle::ReadWithAssociatedData(std::move(*reader), aead,
                                           "associated_data");
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(**parsed_handle, SizeIs(1));
  ASSERT_THAT(*handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT((*parsed_handle)->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((**parsed_handle)[0]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest,
       EncryptedKeysetWrittenByKeysetHandleCanBeParsed) {
  absl::StatusOr<TestOnlyParameters> parameters = NoPrefixParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build(key_gen_config_);
  ASSERT_THAT(handle, IsOk());

  DummyAead aead("keyset encryption aead");

  std::stringbuf encrypted_keyset;
  absl::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(
          std::make_unique<std::ostream>(&encrypted_keyset));
  ASSERT_THAT(writer, IsOk());

  ASSERT_THAT(
      handle->WriteWithAssociatedData(writer->get(), aead, "associated_data"),
      IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(encrypted_keyset.str(), aead,
                                           "associated_data");
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*parsed_handle, SizeIs(1));
  ASSERT_THAT(*handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

// Encrypted keyset containing `kHexSerializedTestVectorKeyset`, encrypted with
// `DummyAead("keyset encryption aead")` and associated data "associatedData".
// It is the binary serialization of an `EncryptedKeyset` proto whose
// `encrypted_keyset` is the `DummyAead` ciphertext
// "22:14:keyset encryption aeadassociatedData" || serialized keyset.
TEST_F(SerializeKeysetToProtoKeysetFormatTest, EncryptedKeysetTestVector) {
  DummyAead keyset_encryption_aead("keyset encryption aead");

  std::string encrypted_keyset = test::HexDecodeOrDie(
      "12860132323a31343a6b657973657420656e6372797074696f6e20616561646173736f63"
      "696174656444617461088486880812550a4a0a32747970652e676f6f676c65617069732e"
      "636f6d2f676f6f676c652e63727970746f2e74696e6b2e546573744f6e6c794b65791212"
      "1210000102030405060708090a0b0c0d0e0f1801100118848688082001");
  std::string associated_data = "associatedData";
  absl::StatusOr<KeysetHandle> keyset_handle =
      ParseKeysetFromEncryptedKeysetFormat(
          encrypted_keyset, keyset_encryption_aead, associated_data);
  ASSERT_THAT(keyset_handle, IsOk());
  ASSERT_THAT(*keyset_handle, SizeIs(1));

  absl::StatusOr<TestOnlySymmetricKey> expected_key = TestVectorKey();
  ASSERT_THAT(expected_key, IsOk());
  EXPECT_THAT((*keyset_handle)[0].IsPrimary(), IsTrue());
  EXPECT_THAT((*keyset_handle)[0].GetStatus(), Eq(KeyStatus::kEnabled));
  EXPECT_THAT((*keyset_handle)[0].GetId(), Eq(0x01020304));
  EXPECT_THAT(*(*keyset_handle)[0].GetKey(), Eq(*expected_key));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
