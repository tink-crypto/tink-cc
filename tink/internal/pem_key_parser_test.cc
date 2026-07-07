// Copyright 2026 Google Inc.
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

#include "tink/internal/pem_key_parser.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/ec_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::StatusIs;
using ::testing::Eq;

// Generated with:
// openssl genpkey -algorithm ed25519 | openssl pkey -pubout
constexpr absl::string_view kEd25519PrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIEi4HkntDhMSTvueyGqMkz7JBBAjYoejWoQ8g5mt5oO5\n"
    "-----END PRIVATE KEY-----\n";

// Extracted from:
// openssl asn1parse -in private-key.pem -dump
//
// The private key is embedded within the dumped 34 byte hex-encoded OCTET
// STRING value. Discard the first 2 bytes, the remaining 32 bytes is the key.
constexpr absl::string_view kEd25519PrivateKeyBytes =
    "48b81e49ed0e13124efb9ec86a8c933ec90410236287a35a843c8399ade683b9";

// Generated with:
// openssl pkey -in private-key.pem -pubout -out public-key.pem
// Extracted from:
// openssl asn1parse -in public-key.pem -dump
constexpr absl::string_view kEd25519PrivateKeyPubX =
    "8c48bd3f2be9a2e19be264511bbed578163ca7d3cc2efad46c04c725962462da";

constexpr absl::string_view kEd25519PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAjEi9PyvpouGb4mRRG77VeBY8p9PMLvrUbATHJZYkYto=\n"
    "-----END PUBLIC KEY-----\n";

constexpr absl::string_view kEcP256PrivateKey =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIPS5s4/SgXUn5bbveRC85ZTwbYeZDzGi6QBVlJUeKi8voAoGCCqGSM49\n"
    "AwEHoUQDQgAEALAneNp7e/1wlMNvhH6zKzB3VH2knI7PZn96zDFFaTxxDzBErxz+\n"
    "VfENdd4Hcpf38nRc8s1s1DBvKqcuNn9zMQ==\n"
    "-----END EC PRIVATE KEY-----\n";

constexpr absl::string_view kEcP256PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEALAneNp7e/1wlMNvhH6zKzB3VH2k\n"
    "nI7PZn96zDFFaTxxDzBErxz+VfENdd4Hcpf38nRc8s1s1DBvKqcuNn9zMQ==\n"
    "-----END PUBLIC KEY-----\n";

TEST(PemKeyParserTest, ParseEd25519PrivateKey) {
  absl::StatusOr<Ed25519Key> ed25519_priv_key =
      ParseEd25519PrivateKey(kEd25519PrivateKey);
  ASSERT_THAT(ed25519_priv_key, IsOk());
  EXPECT_THAT(test::HexEncode(util::SecretDataAsStringView(
                  (*ed25519_priv_key).private_key)),
              Eq(kEd25519PrivateKeyBytes));
  EXPECT_THAT(test::HexEncode((*ed25519_priv_key).public_key),
              Eq(kEd25519PrivateKeyPubX));
}

TEST(PemKeyParserTest, ParseEd25519PublicKeyFails) {
  EXPECT_THAT(ParseEd25519PrivateKey(kEd25519PublicKey),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemKeyParserTest, ParseEcDsaPublicKeyFails) {
  EXPECT_THAT(ParseEd25519PrivateKey(kEcP256PublicKey),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemKeyParserTest, ParseEcDsaPrivateKeyFails) {
  EXPECT_THAT(ParseEd25519PrivateKey(kEcP256PrivateKey),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
