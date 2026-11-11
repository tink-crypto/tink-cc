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

#include "tink/internal/testing/test_only_key_managers.h"

#include <cstdint>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/internal/testing/test_only_key.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/random.h"
#include "tink/util/test_util.h"
#include "proto/test_only_key.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::google::crypto::tink::TestOnlyKey;
using ::google::crypto::tink::TestOnlyKeyFormat;
using ::google::crypto::tink::TestOnlyPrivateKey;
using ::google::crypto::tink::TestOnlyPublicKey;

KeyTemplate MakeKeyTemplate(absl::string_view type_url,
                            OutputPrefixType output_prefix_type) {
  TestOnlyKeyFormat key_format;
  key_format.set_key_size(kTestOnlyKeySizeInBytes);
  KeyTemplate key_template;
  key_template.set_type_url(type_url);
  key_template.set_output_prefix_type(output_prefix_type);
  key_template.set_value(key_format.SerializeAsString());
  return key_template;
}

absl::Status ValidateKeyFormatProto(const TestOnlyKeyFormat& key_format) {
  if (key_format.key_size() == 0) {
    return absl::InvalidArgumentError("Key size must be positive");
  }
  return absl::OkStatus();
}

absl::Status ValidateVersion(uint32_t version) {
  if (version != 0) {
    return absl::InvalidArgumentError("Only version 0 keys are accepted");
  }
  return absl::OkStatus();
}

// The public key material is the reversed private key material.
std::string ComputePublicKeyMaterial(absl::string_view private_key_material) {
  return std::string(private_key_material.rbegin(),
                     private_key_material.rend());
}

class AeadFactory : public TestOnlyKeyTypeManager::PrimitiveFactory<Aead> {
  absl::StatusOr<std::unique_ptr<Aead>> Create(
      const TestOnlyKey& key) const override {
    return {std::make_unique<test::DummyAead>(
        absl::BytesToHexString(key.key_value()))};
  }
};

class PublicKeySignFactory
    : public TestOnlyPrivateKeyTypeManager::PrimitiveFactory<PublicKeySign> {
  absl::StatusOr<std::unique_ptr<PublicKeySign>> Create(
      const TestOnlyPrivateKey& key) const override {
    return {std::make_unique<test::DummyPublicKeySign>(
        absl::BytesToHexString(key.public_key().key_value()))};
  }
};

class PublicKeyVerifyFactory
    : public TestOnlyPublicKeyTypeManager::PrimitiveFactory<PublicKeyVerify> {
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> Create(
      const TestOnlyPublicKey& key) const override {
    return {std::make_unique<test::DummyPublicKeyVerify>(
        absl::BytesToHexString(key.key_value()))};
  }
};

}  // namespace

KeyTemplate TestOnlyKeyTemplate(OutputPrefixType output_prefix_type) {
  return MakeKeyTemplate(kTestOnlyKeyTypeUrl, output_prefix_type);
}

KeyTemplate TestOnlyPrivateKeyTemplate(OutputPrefixType output_prefix_type) {
  return MakeKeyTemplate(kTestOnlyPrivateKeyTypeUrl, output_prefix_type);
}

TestOnlyKeyTypeManager::TestOnlyKeyTypeManager()
    : KeyTypeManager(std::make_unique<AeadFactory>()) {}

absl::Status TestOnlyKeyTypeManager::ValidateKey(const TestOnlyKey& key) const {
  return ValidateVersion(key.version());
}

absl::Status TestOnlyKeyTypeManager::ValidateKeyFormat(
    const TestOnlyKeyFormat& key_format) const {
  return ValidateKeyFormatProto(key_format);
}

absl::StatusOr<TestOnlyKey> TestOnlyKeyTypeManager::CreateKey(
    const TestOnlyKeyFormat& key_format) const {
  TestOnlyKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  return key;
}

TestOnlyPrivateKeyTypeManager::TestOnlyPrivateKeyTypeManager()
    : PrivateKeyTypeManager(std::make_unique<PublicKeySignFactory>()) {}

absl::Status TestOnlyPrivateKeyTypeManager::ValidateKey(
    const TestOnlyPrivateKey& key) const {
  absl::Status status = ValidateVersion(key.version());
  if (!status.ok()) {
    return status;
  }
  if (key.public_key().key_value() !=
      ComputePublicKeyMaterial(key.key_value())) {
    return absl::InvalidArgumentError(
        "The public key doesn't match the private key");
  }
  return ValidateVersion(key.public_key().version());
}

absl::Status TestOnlyPrivateKeyTypeManager::ValidateKeyFormat(
    const TestOnlyKeyFormat& key_format) const {
  return ValidateKeyFormatProto(key_format);
}

absl::StatusOr<TestOnlyPrivateKey> TestOnlyPrivateKeyTypeManager::CreateKey(
    const TestOnlyKeyFormat& key_format) const {
  TestOnlyPrivateKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  key.mutable_public_key()->set_version(get_version());
  key.mutable_public_key()->set_key_value(
      ComputePublicKeyMaterial(key.key_value()));
  return key;
}

absl::StatusOr<TestOnlyPublicKey> TestOnlyPrivateKeyTypeManager::GetPublicKey(
    const TestOnlyPrivateKey& private_key) const {
  return private_key.public_key();
}

TestOnlyPublicKeyTypeManager::TestOnlyPublicKeyTypeManager()
    : KeyTypeManager(std::make_unique<PublicKeyVerifyFactory>()) {}

absl::Status TestOnlyPublicKeyTypeManager::ValidateKey(
    const TestOnlyPublicKey& key) const {
  return ValidateVersion(key.version());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
