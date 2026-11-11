// Copyright 2026 Google LLC
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

#ifndef TINK_INTERNAL_TESTING_TEST_ONLY_KEY_MANAGERS_H_
#define TINK_INTERNAL_TESTING_TEST_ONLY_KEY_MANAGERS_H_

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Legacy key managers for the test-only key types of `test_only_key.h`, for
// tests that use the legacy key manager API. They provide no security at all:
// their primitives are the dummy primitives of `util/test_util.h`.
//
// The keys are the test-only protos of `proto/test_only_key.proto`:
//   * symmetric keys (type URL `kTestOnlyKeyTypeUrl`): `TestOnlyKey`;
//   * private keys (type URL `kTestOnlyPrivateKeyTypeUrl`):
//     `TestOnlyPrivateKey`;
//   * public keys (type URL `kTestOnlyPublicKeyTypeUrl`): `TestOnlyPublicKey`,
//     whose key material is the reversed key material of the private key;
//   * key formats: `TestOnlyKeyFormat`.

inline constexpr absl::string_view kTestOnlyPrivateKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.TestOnlyPrivateKey";
inline constexpr absl::string_view kTestOnlyPublicKeyTypeUrl =
    "type.googleapis.com/google.crypto.tink.TestOnlyPublicKey";

// Returns a key template for `TestOnlyKeyTypeManager`.
google::crypto::tink::KeyTemplate TestOnlyKeyTemplate(
    google::crypto::tink::OutputPrefixType output_prefix_type =
        google::crypto::tink::OutputPrefixType::TINK);

// Returns a key template for `TestOnlyPrivateKeyTypeManager`.
google::crypto::tink::KeyTemplate TestOnlyPrivateKeyTemplate(
    google::crypto::tink::OutputPrefixType output_prefix_type =
        google::crypto::tink::OutputPrefixType::TINK);

// Key type manager for symmetric test-only keys (type URL
// `kTestOnlyKeyTypeUrl`). Its `Aead` primitives are `test::DummyAead`s.
class TestOnlyKeyTypeManager
    : public KeyTypeManager<google::crypto::tink::TestOnlyKey,
                            google::crypto::tink::TestOnlyKeyFormat,
                            List<Aead>> {
 public:
  TestOnlyKeyTypeManager();

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::TestOnlyKey& key) const override;

  absl::Status ValidateKeyFormat(
      const google::crypto::tink::TestOnlyKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::TestOnlyKey> CreateKey(
      const google::crypto::tink::TestOnlyKeyFormat& key_format) const override;

 private:
  const std::string key_type_ = std::string(kTestOnlyKeyTypeUrl);
};

// Key type manager for test-only private keys (type URL
// `kTestOnlyPrivateKeyTypeUrl`). Its `PublicKeySign` primitives are
// `test::DummyPublicKeySign`s, which can be verified by the
// `test::DummyPublicKeyVerify` primitives of `TestOnlyPublicKeyTypeManager`
// for the corresponding public key.
class TestOnlyPrivateKeyTypeManager
    : public PrivateKeyTypeManager<google::crypto::tink::TestOnlyPrivateKey,
                                   google::crypto::tink::TestOnlyKeyFormat,
                                   google::crypto::tink::TestOnlyPublicKey,
                                   List<PublicKeySign>> {
 public:
  TestOnlyPrivateKeyTypeManager();

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::TestOnlyPrivateKey& key) const override;

  absl::Status ValidateKeyFormat(
      const google::crypto::tink::TestOnlyKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::TestOnlyPrivateKey> CreateKey(
      const google::crypto::tink::TestOnlyKeyFormat& key_format) const override;

  absl::StatusOr<google::crypto::tink::TestOnlyPublicKey> GetPublicKey(
      const google::crypto::tink::TestOnlyPrivateKey& private_key)
      const override;

 private:
  const std::string key_type_ = std::string(kTestOnlyPrivateKeyTypeUrl);
};

// Key type manager for test-only public keys (type URL
// `kTestOnlyPublicKeyTypeUrl`). Its `PublicKeyVerify` primitives are
// `test::DummyPublicKeyVerify`s.
class TestOnlyPublicKeyTypeManager
    : public KeyTypeManager<google::crypto::tink::TestOnlyPublicKey, void,
                            List<PublicKeyVerify>> {
 public:
  TestOnlyPublicKeyTypeManager();

  uint32_t get_version() const override { return 0; }

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PUBLIC;
  }

  const std::string& get_key_type() const override { return key_type_; }

  absl::Status ValidateKey(
      const google::crypto::tink::TestOnlyPublicKey& key) const override;

 private:
  const std::string key_type_ = std::string(kTestOnlyPublicKeyTypeUrl);
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_TESTING_TEST_ONLY_KEY_MANAGERS_H_
