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
////////////////////////////////////////////////////////////////////////////////

#include "tink/config/global_registry.h"

#include <cstdint>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

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
      return absl::make_unique<FakePrimitive>(key.key_value());
    }
  };

  FakeKeyTypeManager()
      : KeyTypeManager(absl::make_unique<FakePrimitiveFactory>()) {}

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

class FakePrimitiveWrapper
    : public PrimitiveWrapper<FakePrimitive, FakePrimitive> {
 public:
  absl::StatusOr<std::unique_ptr<FakePrimitive>> Wrap(
      std::unique_ptr<PrimitiveSet<FakePrimitive>> primitive_set)
      const override {
    return absl::make_unique<FakePrimitive>(
        primitive_set->get_primary()->get_primitive().get());
  }
};

TEST(GlobalRegistryTest, GenerateNewKeysetHandleFromKeyGenConfig) {
  Registry::Reset();

  KeyTemplate templ;
  templ.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  templ.set_output_prefix_type(OutputPrefixType::TINK);
  EXPECT_THAT(
      KeysetHandle::GenerateNew(templ, KeyGenConfigGlobalRegistry()).status(),
      StatusIs(absl::StatusCode::kNotFound));

  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<FakeKeyTypeManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  EXPECT_THAT(
      KeysetHandle::GenerateNew(templ, KeyGenConfigGlobalRegistry()).status(),
      IsOk());
}

TEST(GlobalRegistryTest, GetPrimitiveFromConfig) {
  Registry::Reset();
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<FakeKeyTypeManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());

  KeyTemplate templ;
  templ.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  templ.set_output_prefix_type(OutputPrefixType::TINK);
  absl::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(templ, KeyGenConfigGlobalRegistry());
  ASSERT_THAT(handle, IsOk());
  EXPECT_THAT(
      (*handle)->GetPrimitive<FakePrimitive>(ConfigGlobalRegistry()).status(),
      StatusIs(absl::StatusCode::kNotFound));

  Registry::Reset();
  ASSERT_THAT(
      Registry::RegisterKeyTypeManager(absl::make_unique<FakeKeyTypeManager>(),
                                       /*new_key_allowed=*/true),
      IsOk());
  ASSERT_THAT(Registry::RegisterPrimitiveWrapper(
                  absl::make_unique<FakePrimitiveWrapper>()),
              IsOk());

  EXPECT_THAT((*handle)->GetPrimitive<FakePrimitive>(ConfigGlobalRegistry()),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
