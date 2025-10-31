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

#include "tink/internal/keyset_wrapper_store.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/registry_impl.h"
#include "tink/key.h"
#include "tink/mac.h"
#include "tink/mac/mac_wrapper.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using AesGcmKeyProto = ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;

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

class FakePrimitiveWrapper2
    : public PrimitiveWrapper<FakePrimitive, FakePrimitive> {
 public:
  absl::StatusOr<std::unique_ptr<FakePrimitive>> Wrap(
      std::unique_ptr<PrimitiveSet<FakePrimitive>> primitive_set)
      const override {
    return absl::make_unique<FakePrimitive>(
        primitive_set->get_primary()->get_primitive().get());
  }
};

std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(const Key& key)>
FakePrimitiveGetterFromKey() {
  return [](const Key& key) {
    return absl::make_unique<FakePrimitive>("fake key material");
  };
}

std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(const Key& key)>
FailingFakePrimitiveGetterFromKey() {
  return [](const Key& key) {
    return absl::Status(absl::StatusCode::kUnimplemented, "Not implemented.");
  };
}

std::string AddAesGcmKeyToKeyset(Keyset& keyset, uint32_t key_id,
                                 OutputPrefixType output_prefix_type,
                                 KeyStatusType key_status_type) {
  AesGcmKeyProto key;
  key.set_version(0);
  key.set_key_value(subtle::Random::GetRandomBytes(16));
  KeyData key_data;
  key_data.set_value(key.SerializeAsString());
  key_data.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  test::AddKeyData(key_data, key_id, output_prefix_type, key_status_type,
                   &keyset);
  return std::string(key.key_value());
}

// Returns the function that relies on `registry` to transform `key_data` into
// FakePrimitive.
absl::StatusOr<std::function<
    absl::StatusOr<std::unique_ptr<FakePrimitive>>(const KeyData&)>>
PrimitiveGetter(RegistryImpl& registry) {
  absl::Status status =
      registry.RegisterKeyTypeManager<AesGcmKeyProto, AesGcmKeyFormat,
                                      List<FakePrimitive>>(
          absl::make_unique<FakeKeyTypeManager>(),
          /*new_key_allowed=*/true);
  if (!status.ok()) {
    return status;
  }
  return [&registry](const KeyData& key_data) {
    return registry.GetPrimitive<FakePrimitive>(key_data);
  };
}

TEST(KeysetWrapperStoreTest, Add) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  EXPECT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());
}

TEST(KeysetWrapperStoreTest, AddNull) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  EXPECT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  /*wrapper=*/nullptr, *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KeysetWrapperStoreTest, AddWrappersForDifferentPrimitivesSucceeds) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  std::function<absl::StatusOr<std::unique_ptr<Mac>>(const KeyData& key_data)>
      primitive_getter_mac = [&registry](const KeyData& key_data) {
        return registry.GetPrimitive<Mac>(key_data);
      };
  std::function<absl::StatusOr<std::unique_ptr<Mac>>(const Key& key)>
      primitive_getter_mac_from_key = [](const Key& key) {
        return absl::Status(absl::StatusCode::kUnimplemented,
                            "Not implemented.");
      };
  EXPECT_THAT((store.Add<Mac, Mac>(absl::make_unique<MacWrapper>(),
                                   primitive_getter_mac,
                                   primitive_getter_mac_from_key)),
              IsOk());
}

TEST(KeysetWrapperStoreTest, AddSameWrapperTwiceSucceeds) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());
  EXPECT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());
}

TEST(KeysetWrapperStoreTest, AddDifferentWrappersForSamePrimitiveFails) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());
  EXPECT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper2>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KeysetWrapperStoreTest, GetPrimitiveWrapper) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  absl::StatusOr<const PrimitiveWrapper<FakePrimitive, FakePrimitive>*>
      legacy_wrapper = store.GetPrimitiveWrapper<FakePrimitive>();
  ASSERT_THAT(legacy_wrapper, IsOk());

  Keyset keyset;
  std::string raw_key = AddAesGcmKeyToKeyset(keyset, 13, OutputPrefixType::TINK,
                                             KeyStatusType::ENABLED);
  KeysetInfo keyset_info;
  keyset_info.add_key_info();
  keyset_info.mutable_key_info(0)->set_output_prefix_type(
      OutputPrefixType::TINK);
  keyset_info.mutable_key_info(0)->set_key_id(1234543);
  keyset_info.mutable_key_info(0)->set_status(KeyStatusType::ENABLED);
  keyset_info.set_primary_key_id(1234543);
  auto primitive_set = std::make_unique<PrimitiveSet<FakePrimitive>>();
  auto entry = primitive_set->AddPrimitive(
      absl::make_unique<FakePrimitive>(raw_key), keyset_info.key_info(0));
  ASSERT_THAT(entry, IsOk());
  ASSERT_THAT(primitive_set->set_primary(*entry), IsOk());

  absl::StatusOr<std::unique_ptr<FakePrimitive>> legacy_aead =
      (*legacy_wrapper)->Wrap(std::move(primitive_set));
  ASSERT_THAT(legacy_aead, IsOk());
  EXPECT_THAT((*legacy_aead)->get(), Eq(raw_key));
}

TEST(KeysetWrapperStoreTest, GetPrimitiveWrapperNonexistentWrapperFails) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  EXPECT_THAT(store.GetPrimitiveWrapper<Mac>().status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(KeysetWrapperStoreTest, Get) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  absl::StatusOr<const KeysetWrapper<FakePrimitive>*> wrapper =
      store.Get<FakePrimitive>();
  ASSERT_THAT(wrapper, IsOk());

  Keyset keyset;
  std::string raw_key = AddAesGcmKeyToKeyset(keyset, 13, OutputPrefixType::TINK,
                                             KeyStatusType::ENABLED);
  keyset.set_primary_key_id(13);

  absl::StatusOr<std::unique_ptr<FakePrimitive>> aead =
      (*wrapper)->Wrap(keyset, /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());
  EXPECT_THAT((*aead)->get(), Eq(raw_key));
}

TEST(KeysetWrapperStoreTest,
     GetFailingPrimitiveGetterFromKeyFallsBackToKeyData) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FailingFakePrimitiveGetterFromKey())),
              IsOk());

  absl::StatusOr<const KeysetWrapper<FakePrimitive>*> wrapper =
      store.Get<FakePrimitive>();
  ASSERT_THAT(wrapper, IsOk());

  Keyset keyset;
  std::string raw_key = AddAesGcmKeyToKeyset(keyset, 13, OutputPrefixType::TINK,
                                             KeyStatusType::ENABLED);
  keyset.set_primary_key_id(13);

  absl::StatusOr<std::unique_ptr<FakePrimitive>> aead =
      (*wrapper)->Wrap(keyset, /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());
  EXPECT_THAT((*aead)->get(), Eq(raw_key));
}

TEST(KeysetWrapperStoreTest, GetNonexistentWrapperFails) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  EXPECT_THAT(store.Get<Mac>().status(), StatusIs(absl::StatusCode::kNotFound));
}

TEST(KeysetWrapperStoreTest, IsEmpty) {
  KeysetWrapperStore store;
  EXPECT_EQ(store.IsEmpty(), true);

  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());
  EXPECT_THAT(store.IsEmpty(), false);
}

TEST(KeysetWrapperStoreTest, Move) {
  RegistryImpl registry;
  absl::StatusOr<std::function<absl::StatusOr<std::unique_ptr<FakePrimitive>>(
      const KeyData&)>>
      primitive_getter = PrimitiveGetter(registry);
  ASSERT_THAT(primitive_getter, IsOk());

  KeysetWrapperStore store;
  ASSERT_THAT((store.Add<FakePrimitive, FakePrimitive>(
                  absl::make_unique<FakePrimitiveWrapper>(), *primitive_getter,
                  FakePrimitiveGetterFromKey())),
              IsOk());

  absl::StatusOr<const KeysetWrapper<FakePrimitive>*> wrapper =
      store.Get<FakePrimitive>();
  ASSERT_THAT(wrapper, IsOk());

  KeysetWrapperStore new_store = std::move(store);
  wrapper = new_store.Get<FakePrimitive>();
  ASSERT_THAT(wrapper, IsOk());

  Keyset keyset;
  std::string raw_key = AddAesGcmKeyToKeyset(keyset, 13, OutputPrefixType::TINK,
                                             KeyStatusType::ENABLED);
  keyset.set_primary_key_id(13);

  absl::StatusOr<std::unique_ptr<FakePrimitive>> aead =
      (*wrapper)->Wrap(keyset, /*annotations=*/{});
  ASSERT_THAT(aead, IsOk());
  EXPECT_THAT((*aead)->get(), Eq(raw_key));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
