// Copyright 2024 Google LLC
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

#include "tink/json/internal/tink_type_resolver.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "google/protobuf/json/json.h"
#include "google/protobuf/util/type_resolver.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::EncryptedKeyset;
using ::google::crypto::tink::Keyset;
using ::google::protobuf::json::ParseOptions;
using ::testing::Eq;

TEST(TinkTypeResolverTest, ResolveMessageTypeWorks) {
  auto* resolver = internal::GetTinkTypeResolver();

  google::protobuf::Type keyset_type;
  auto status = resolver->ResolveMessageType(
      "type.googleapis.com/google.crypto.tink.Keyset", &keyset_type);
  ASSERT_THAT(status, IsOk());
  EXPECT_THAT(keyset_type.name(), Eq("google.crypto.tink.Keyset"));
}

TEST(TinkTypeResolverTest, ParseKeyset) {
  std::string json_keyset = R"json(
    {
      "primaryKeyId":42,
      "key":[
        {
            "keyData":{
              "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
              "keyMaterialType":"SYMMETRIC",
              "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
            },
            "outputPrefixType":"TINK",
            "keyId": 42,
            "status":"ENABLED"
        }
      ]
    })json";
  ParseOptions parse_options;
  std::string binary_keyset;
  absl::Status status =
      JsonToBinaryString(internal::GetTinkTypeResolver(),
                         "type.googleapis.com/google.crypto.tink.Keyset",
                         json_keyset, &binary_keyset, parse_options);
  ASSERT_THAT(status, IsOk());
  Keyset keyset;
  ASSERT_TRUE(keyset.ParseFromString(binary_keyset));
  EXPECT_THAT(keyset.primary_key_id(), Eq(42));
  EXPECT_THAT(keyset.key_size(), Eq(1));
  EXPECT_THAT(keyset.key(0).output_prefix_type(),
              Eq(google::crypto::tink::TINK));
  EXPECT_THAT(keyset.key(0).key_id(), Eq(42));
  EXPECT_THAT(keyset.key(0).status(), Eq(google::crypto::tink::ENABLED));
  EXPECT_THAT(keyset.key(0).key_data().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(keyset.key(0).key_data().key_material_type(),
              Eq(google::crypto::tink::KeyData::SYMMETRIC));
  EXPECT_THAT(keyset.key(0).key_data().value().length(), Eq(34));
}

TEST(TinkTypeResolverTest, ParseEncryptedKeyset) {
  std::string json_encrypted_keyset = R"json(
  {
    "keysetInfo": {
        "primaryKeyId": 1353288376,
        "keyInfo": [{
            "typeUrl": "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
            "outputPrefixType": "TINK",
            "keyId": 1353288376,
            "status": "ENABLED"
        }]
    },
    "encryptedKeyset": "AOeDD+K9avWgJPATpSkvxEVqMKG1QpWzpSgOWdaY3H8CdTuEjcRWSTwtUKNIzY62C5g4sdHiFRYbHAErW8fZB0rlAfZx6Al43G/exlWzk8CZcrqEX0r/VTFsTNdGb6zmTFqLGqmV54yqsryTazF92qILsPyNuFMxm4AfZ4hUDXmHSYZPOr9FUbYkfYeQQebeUL5GKV8dSInj4l9/xnAdyG92iVqhG5V7KxsymVAVnaj8bP7JPyM2xF1VEt8YtQemibrnBHhOtkZEzUdz88O1A4qHVYW1bb/6tCtfI4dxJrydYB3fTsdjOFYpTvhoFbQTVbSkF5IPbH8acu0Zr4UWpFKDDAlg5SMgVcsxjteBouO0zum7opp2ymN1pFllNuhIDTg0X7pp5AU+8p2wGrSVrkMEFVgWmifL+dFae6KQRvpFd9sCEz4pw7Kx6uqcVsREE8P2JgxLPctMMh021LGVE25+4fjC1vslYlCRCUziZPN8W3BP9xvORxj0y9IvChBmqBcKjT56M+5C26HXWK2U26ZR7OxLIdesLQ\u003d\u003d"
  })json";
  ParseOptions parse_options;
  std::string binary_encrypted_keyset;
  absl::Status status = JsonToBinaryString(
      internal::GetTinkTypeResolver(),
      "type.googleapis.com/google.crypto.tink.EncryptedKeyset",
      json_encrypted_keyset, &binary_encrypted_keyset, parse_options);
  ASSERT_THAT(status, IsOk());
  EncryptedKeyset encrypted_keyset;
  ASSERT_TRUE(encrypted_keyset.ParseFromString(binary_encrypted_keyset));
  EXPECT_THAT(encrypted_keyset.keyset_info().primary_key_id(), Eq(1353288376));
  EXPECT_THAT(encrypted_keyset.keyset_info().key_info().size(), Eq(1));
  EXPECT_THAT(
      encrypted_keyset.keyset_info().key_info(0).type_url(),
      Eq("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
