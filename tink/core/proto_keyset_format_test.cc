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
#include "absl/strings/escaping.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/keyset_reader.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

class SerializeKeysetToProtoKeysetFormatTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = TinkConfig::Register();
    ASSERT_THAT(status, IsOk());
  }
};

util::StatusOr<AesCmacParameters> CmacParameters() {
  return AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                   /*cryptographic_tag_size_in_bytes=*/16,
                                   AesCmacParameters::Variant::kNoPrefix);
}

util::StatusOr<AesGcmParameters> GcmParameters() {
  return AesGcmParameters::Builder()
      .SetKeySizeInBytes(32)
      .SetIvSizeInBytes(12)
      .SetTagSizeInBytes(16)
      .SetVariant(AesGcmParameters::Variant::kTink)
      .Build();
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseSingleKey) {
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
      SecretDataAsStringView(*serialization), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(1));
  ASSERT_THAT(*parsed_handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParseMultipleKeys) {
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
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
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle = ParseKeysetFromProtoKeysetFormat(
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
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<std::string> serialization =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(*handle);
  ASSERT_THAT(serialization, Not(IsOk()));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, ParseNoAccessFails) {
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  crypto::tink::util::StatusOr<SecretData> serialization =
      SerializeKeysetToProtoKeysetFormat(*handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization));
  ASSERT_THAT(parsed_handle, Not(IsOk()));
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, TestVector) {
  std::string serialized_keyset = absl::HexStringToBytes(
      "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f67"
      "6c652e63727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f"
      "5d01759ac1302f7d883f2f4a40025532ee1b11f9e587120410100803180110011895e59b"
      "cc062001");
  crypto::tink::util::StatusOr<KeysetHandle> keyset_handle =
      ParseKeysetFromProtoKeysetFormat(serialized_keyset,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  crypto::tink::util::StatusOr<std::unique_ptr<Mac>> mac =
      (*keyset_handle).GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  ASSERT_THAT(
      (*mac)->VerifyMac(
          absl::HexStringToBytes("016986f2956092d259136923c6f4323557714ec499"),
          "data"),
      IsOk());
}

TEST_F(SerializeKeysetToProtoKeysetFormatTest, SerializeAndParsePublicKey) {
  util::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());


  crypto::tink::util::StatusOr<SecretData> serialization1 =
      SerializeKeysetToProtoKeysetFormat(**public_handle,
                                         InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  crypto::tink::util::StatusOr<std::string> serialization2 =
      SerializeKeysetWithoutSecretToProtoKeysetFormat(**public_handle);
  ASSERT_THAT(serialization2, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle1 =
      ParseKeysetFromProtoKeysetFormat(SecretDataAsStringView(*serialization1),
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle1, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle2 =
      ParseKeysetWithoutSecretFromProtoKeysetFormat(
          SecretDataAsStringView(*serialization1));
  ASSERT_THAT(parsed_handle2, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle3 =
      ParseKeysetFromProtoKeysetFormat(*serialization2,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle3, IsOk());
  util::StatusOr<KeysetHandle> parsed_handle4 =
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
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<AesGcmParameters> aead_parameters = GcmParameters();
  ASSERT_THAT(aead_parameters, IsOk());

  util::StatusOr<KeysetHandle> aead_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *aead_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(aead_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      aead_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  util::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, **aead,
                                             "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(*encrypted_keyset, **aead,
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
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
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
          .Build();
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<AesGcmParameters> aead_parameters = GcmParameters();
  ASSERT_THAT(aead_parameters, IsOk());

  util::StatusOr<KeysetHandle> aead_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *aead_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(aead_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      aead_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  util::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, **aead,
                                             "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  util::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(*encrypted_keyset, **aead,
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
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<AesGcmParameters> aead_parameters = GcmParameters();
  ASSERT_THAT(aead_parameters, IsOk());

  util::StatusOr<KeysetHandle> aead_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *aead_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(aead_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      aead_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  util::StatusOr<std::string> encrypted_keyset =
      SerializeKeysetToEncryptedKeysetFormat(*handle, **aead,
                                             "associated_data");
  ASSERT_THAT(encrypted_keyset, IsOk());

  util::StatusOr<std::unique_ptr<KeysetReader>> reader =
      BinaryKeysetReader::New(*encrypted_keyset);
  ASSERT_THAT(reader, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> parsed_handle =
      KeysetHandle::ReadWithAssociatedData(std::move(*reader), **aead,
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
  util::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<AesGcmParameters> aead_parameters = GcmParameters();
  ASSERT_THAT(aead_parameters, IsOk());

  util::StatusOr<KeysetHandle> aead_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *aead_parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(aead_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      aead_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(aead, IsOk());

  std::stringbuf encrypted_keyset;
  util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> writer =
      BinaryKeysetWriter::New(
          absl::make_unique<std::ostream>(&encrypted_keyset));
  ASSERT_THAT(writer, IsOk());

  ASSERT_THAT(
      handle->WriteWithAssociatedData(writer->get(), **aead, "associated_data"),
      IsOk());

  util::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromEncryptedKeysetFormat(encrypted_keyset.str(), **aead,
                                           "associated_data");
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*parsed_handle, SizeIs(1));
  ASSERT_THAT(*handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

// Test vector copied from parseEncryptedKeysetFromTestVector() in
// TinkProtoKeysetFormatTest.java.
TEST_F(SerializeKeysetToProtoKeysetFormatTest, EncryptedKeysetTestVector) {
  std::string serialized_keyset_encryption_keyset = absl::HexStringToBytes(
      "08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f67"
      "6c652e63727970746f2e74696e6b2e4165734561784b65791216120208101a10e5d7d0cd"
      "d649e81e7952260689b2e1971801100118b891f5a2042001");
  util::StatusOr<KeysetHandle> keyset_encryption_handle =
      ParseKeysetFromProtoKeysetFormat(serialized_keyset_encryption_keyset,
                                       InsecureSecretKeyAccess::Get());
  ASSERT_THAT(keyset_encryption_handle, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> keyset_encryption_aead =
      keyset_encryption_handle->GetPrimitive<Aead>(ConfigGlobalRegistry());
  ASSERT_THAT(keyset_encryption_aead, IsOk());

  std::string encrypted_mac_keyset = absl::HexStringToBytes(
      "12950101445d48b8b5f591efaf73a46df9ebd7b6ac471cc0cf4f815a4f012fcaffc8f0b2"
      "b10b30c33194f0b291614bd8e1d2e80118e5d6226b6c41551e104ef8cd8ee20f1c14c1b8"
      "7f6eed5fb04a91feafaacbf6f368519f36f97f7d08b24c8e71b5e620c4f69615ef047939"
      "1666e2fb32e46b416893fc4e564ba927b22ebff2a77bd3b5b8d5afa162cbd35c94c155cd"
      "fa13c8a9c964cde21a4208f5909ce901123a0a2e747970652e676f6f676c65617069732e"
      "636f6d2f676f6f676c652e63727970746f2e74696e6b2e486d61634b6579100118f5909c"
      "e9012001");
  std::string associated_data = absl::HexStringToBytes("abcdef330012");
  util::StatusOr<KeysetHandle> mac_handle =
      ParseKeysetFromEncryptedKeysetFormat(
          encrypted_mac_keyset, **keyset_encryption_aead, associated_data);
  ASSERT_THAT(mac_handle, IsOk());

  util::StatusOr<std::unique_ptr<Mac>> mac =
      (*mac_handle).GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac, IsOk());
  ASSERT_THAT(
      (*mac)->VerifyMac(
          absl::HexStringToBytes("011d270875989dd6fbd5f54dbc9520bb41efd058d5"),
          ""),
      IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
