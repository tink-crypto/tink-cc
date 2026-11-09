// Copyright 2026 Google LLC
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

#include "tink/internal/keyset_handle_access.h"

#include <cstdint>
#include <memory>
#include <string>
#include <typeindex>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/absl_check.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/annotations.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/legacy_annotations.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/util/secret_proto.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::google::crypto::tink::Keyset;
using ::testing::Eq;
using ::testing::Pair;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

// Returns a keyset with a single primary ECDSA key, and sets `key_id` to its
// ID.
//
// Uses ECDSA instead of AES-GCM because this test is in `tink.sandblaze`, which
// compiles Tink against OpenSSL, and the `AesGcmKeyManager` only supports
// BoringSSL.
Keyset CreateKeyset(uint32_t& key_id) {
  KeyGenConfiguration key_gen_config;
  ABSL_CHECK_OK(internal::KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
      std::make_unique<EcdsaSignKeyManager>(),
      std::make_unique<EcdsaVerifyKeyManager>(), key_gen_config));

  Keyset keyset;
  absl::StatusOr<uint32_t> id = KeysetHandleAccess::AddToKeyset(
      SignatureKeyTemplates::EcdsaP256(), /*as_primary=*/true, key_gen_config,
      &keyset);
  ABSL_CHECK_OK(id);
  key_id = *id;
  return keyset;
}

TEST(KeysetHandleAccessTest, AddToKeyset) {
  uint32_t key_id;
  Keyset keyset = CreateKeyset(key_id);

  ASSERT_THAT(keyset.key(), SizeIs(1));
  EXPECT_THAT(keyset.key(0).key_id(), Eq(key_id));
  EXPECT_THAT(keyset.primary_key_id(), Eq(key_id));
}

TEST(KeysetHandleAccessTest, CreateAndGetKeyset) {
  uint32_t key_id;
  Keyset keyset = CreateKeyset(key_id);

  KeysetHandle handle =
      KeysetHandleAccess::Create(util::SecretProto<Keyset>(keyset));

  ASSERT_THAT(handle.size(), Eq(1));
  EXPECT_THAT(handle[0].GetId(), Eq(key_id));
  EXPECT_TRUE(handle[0].IsPrimary());
  const Keyset& handle_keyset = KeysetHandleAccess::GetKeyset(handle);
  EXPECT_THAT(handle_keyset.SerializeAsString(),
              Eq(keyset.SerializeAsString()));
}

TEST(KeysetHandleAccessTest, GetEntriesFromKeysetAndCreateWithEntries) {
  uint32_t key_id;
  Keyset keyset = CreateKeyset(key_id);

  absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandleAccess::GetEntriesFromKeyset(keyset);
  ASSERT_THAT(entries, IsOk());
  ASSERT_THAT(*entries, SizeIs(1));
  EXPECT_THAT((*entries)[0]->GetId(), Eq(key_id));
  EXPECT_TRUE((*entries)[0]->IsPrimary());

  KeysetHandle handle = KeysetHandleAccess::Create(
      util::SecretProto<Keyset>(keyset), *std::move(entries));

  ASSERT_THAT(handle.size(), Eq(1));
  EXPECT_THAT(handle[0].GetId(), Eq(key_id));
  EXPECT_TRUE(handle[0].IsPrimary());
}

TEST(KeysetHandleAccessTest, CreateWithEntriesAndAnnotations) {
  uint32_t key_id;
  Keyset keyset = CreateKeyset(key_id);
  absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandleAccess::GetEntriesFromKeyset(keyset);
  ASSERT_THAT(entries, IsOk());
  absl::flat_hash_map<std::type_index, std::unique_ptr<Annotations>>
      annotations;
  annotations[typeid(LegacyAnnotations)] = std::make_unique<LegacyAnnotations>(
      absl::flat_hash_map<std::string, std::string>{{"key", "value"}});

  KeysetHandle handle =
      KeysetHandleAccess::Create(util::SecretProto<Keyset>(keyset),
                                 *std::move(entries), std::move(annotations));

  ASSERT_THAT(handle.size(), Eq(1));
  EXPECT_THAT(handle[0].GetId(), Eq(key_id));
  absl::StatusOr<const LegacyAnnotations&> handle_annotations =
      handle.GetAnnotations<LegacyAnnotations>();
  ASSERT_THAT(handle_annotations, IsOk());
  EXPECT_THAT(handle_annotations->GetMap(),
              UnorderedElementsAre(Pair("key", "value")));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
