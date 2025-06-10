// Copyright 2025 Google LLC
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

#include "tink/json/json_proto_keyset_format.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/json/json.h"
#include "tink/config/global_registry.h"
#include "tink/config/tink_config.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/json/internal/tink_type_resolver.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/secret_data.h"
#include "tink/signature/ed25519_parameters.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::SecretDataAsStringView;
using ::google::protobuf::json::PrintOptions;
using ::testing::Eq;
using ::testing::Not;
using ::testing::SizeIs;

const char kKeysetTypeUrl[] = "type.googleapis.com/google.crypto.tink.Keyset";

class SerializeKeysetToJsonProtoKeysetFormatTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = TinkConfig::Register();
    ASSERT_THAT(status, IsOk());
  }
};

absl::StatusOr<AesCmacParameters> CmacParameters() {
  return AesCmacParameters::Create(/*key_size_in_bytes=*/32,
                                   /*cryptographic_tag_size_in_bytes=*/16,
                                   AesCmacParameters::Variant::kNoPrefix);
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest, SerializeAndParseSingleKey) {
  absl::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization =
      SerializeKeysetToJsonProtoKeysetFormat(*handle,
                                             InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromJsonProtoKeysetFormat(
          SecretDataAsStringView(*serialization),
          InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(1));
  ASSERT_THAT(*parsed_handle, SizeIs(1));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest,
       SerializeAndParseMultipleKeys) {
  absl::StatusOr<AesCmacParameters> parameters = CmacParameters();
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
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization =
      SerializeKeysetToJsonProtoKeysetFormat(*handle,
                                             InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetFromJsonProtoKeysetFormat(
          SecretDataAsStringView(*serialization),
          InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle, IsOk());
  ASSERT_THAT(*handle, SizeIs(3));
  ASSERT_THAT(*parsed_handle, SizeIs(3));

  ASSERT_THAT(handle->Validate(), IsOk());
  ASSERT_THAT(parsed_handle->Validate(), IsOk());
  EXPECT_THAT((*handle)[0], Eq((*parsed_handle)[0]));
  EXPECT_THAT((*handle)[1], Eq((*parsed_handle)[1]));
  EXPECT_THAT((*handle)[2], Eq((*parsed_handle)[2]));
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest, SerializeNoAccessFails) {
  absl::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<std::string> serialization =
      SerializeKeysetWithoutSecretToJsonProtoKeysetFormat(*handle);
  ASSERT_THAT(serialization, Not(IsOk()));
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest, ParseNoAccessFails) {
  absl::StatusOr<AesCmacParameters> parameters = CmacParameters();
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());

  absl::StatusOr<SecretData> serialization =
      SerializeKeysetToJsonProtoKeysetFormat(*handle,
                                             InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle =
      ParseKeysetWithoutSecretFromJsonProtoKeysetFormat(
          SecretDataAsStringView(*serialization));
  ASSERT_THAT(parsed_handle, Not(IsOk()));
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest, TestVector) {
  std::string serialized_keyset = test::HexDecodeOrDie(
      "0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f67"
      "6c652e63727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3513f"
      "5d01759ac1302f7d883f2f4a40025532ee1b11f9e587120410100803180110011895e59b"
      "cc062001");
  PrintOptions options;
  std::string json_serialized_keyset;
  absl::Status status =
      BinaryToJsonString(internal::GetTinkTypeResolver(), kKeysetTypeUrl,
                         serialized_keyset, &json_serialized_keyset, options);
  ASSERT_THAT(status, IsOk());
  absl::StatusOr<KeysetHandle> keyset_handle =
      ParseKeysetFromJsonProtoKeysetFormat(json_serialized_keyset,
                                           InsecureSecretKeyAccess::Get());
  ASSERT_THAT(keyset_handle.status(), IsOk());
  absl::StatusOr<std::unique_ptr<Mac>> mac =
      (*keyset_handle).GetPrimitive<crypto::tink::Mac>(ConfigGlobalRegistry());
  ASSERT_THAT(mac.status(), IsOk());
  ASSERT_THAT(
      (*mac)->VerifyMac(
          test::HexDecodeOrDie("016986f2956092d259136923c6f4323557714ec499"),
          "data"),
      IsOk());
}

TEST_F(SerializeKeysetToJsonProtoKeysetFormatTest, SerializeAndParsePublicKey) {
  absl::StatusOr<Ed25519Parameters> parameters =
      Ed25519Parameters::Create(Ed25519Parameters::Variant::kNoPrefix);
  ASSERT_THAT(parameters, IsOk());

  absl::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableParams(
              *parameters, KeyStatus::kEnabled, /*is_primary=*/true,
              /*id=*/123))
          .Build();
  ASSERT_THAT(handle, IsOk());
  absl::StatusOr<std::unique_ptr<KeysetHandle>> public_handle =
      handle->GetPublicKeysetHandle(KeyGenConfigGlobalRegistry());
  ASSERT_THAT(public_handle, IsOk());

  absl::StatusOr<SecretData> serialization1 =
      SerializeKeysetToJsonProtoKeysetFormat(**public_handle,
                                             InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  absl::StatusOr<std::string> serialization2 =
      SerializeKeysetWithoutSecretToJsonProtoKeysetFormat(**public_handle);
  ASSERT_THAT(serialization2, IsOk());

  absl::StatusOr<KeysetHandle> parsed_handle1 =
      ParseKeysetFromJsonProtoKeysetFormat(
          SecretDataAsStringView(*serialization1),
          InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle1, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle2 =
      ParseKeysetWithoutSecretFromJsonProtoKeysetFormat(
          SecretDataAsStringView(*serialization1));
  ASSERT_THAT(parsed_handle2, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle3 =
      ParseKeysetFromJsonProtoKeysetFormat(*serialization2,
                                           InsecureSecretKeyAccess::Get());
  ASSERT_THAT(parsed_handle3, IsOk());
  absl::StatusOr<KeysetHandle> parsed_handle4 =
      ParseKeysetWithoutSecretFromJsonProtoKeysetFormat(*serialization2);
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

}  // namespace
}  // namespace tink
}  // namespace crypto
