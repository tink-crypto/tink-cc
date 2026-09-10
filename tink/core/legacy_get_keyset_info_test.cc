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

#include "tink/legacy_get_keyset_info.h"

#include <memory>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/keyset_handle.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::AddRawKey;
using ::crypto::tink::test::AddTinkKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

TEST(LegacyGetKeysetInfoTest, GetKeysetInfo) {
  Keyset keyset;
  Keyset::Key key;
  AddTinkKey("some_key_type", 42, key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddTinkKey(absl::StrCat("more key type", i), i, key, KeyStatusType::ENABLED,
               KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  AddRawKey("some_other_key_type", 10, key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);
  for (int i = 0; i < 10; ++i) {
    AddRawKey(absl::StrCat("more key type", i + 100), i + 100, key,
              KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);
  }
  keyset.set_primary_key_id(42);

  std::unique_ptr<KeysetHandle> handle =
      TestKeysetHandle::GetKeysetHandle(keyset);
  google::crypto::tink::KeysetInfo keyset_info = LegacyGetKeysetInfo(*handle);

  EXPECT_EQ(keyset.primary_key_id(), keyset_info.primary_key_id());
  for (int i = 0; i < keyset.key_size(); ++i) {
    auto key_info = keyset_info.key_info(i);
    auto key = keyset.key(i);
    EXPECT_EQ(key.key_data().type_url(), key_info.type_url());
    EXPECT_EQ(key.status(), key_info.status());
    EXPECT_EQ(key.key_id(), key_info.key_id());
    EXPECT_EQ(key.output_prefix_type(), key_info.output_prefix_type());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
