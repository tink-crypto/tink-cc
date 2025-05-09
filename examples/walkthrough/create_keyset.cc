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

#include "walkthrough/create_keyset.h"

// [START tink_walkthrough_create_keyset]
#include <memory>

#include "absl/status/statusor.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/config/global_registry.h"
#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

namespace tink_walkthrough {

using ::crypto::tink::KeysetHandle;
using ::google::crypto::tink::KeyTemplate;

// Creates a keyset with a single AES128-GCM key and return a handle to it.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
absl::StatusOr<std::unique_ptr<KeysetHandle>> CreateAead128GcmKeyset() {
  // Tink provides pre-baked templates. For example, we generate a key template
  // for AES128-GCM.
  KeyTemplate key_template = crypto::tink::AeadKeyTemplates::Aes128Gcm();
  // This will generate a new keyset with only *one* key and return a keyset
  // handle to it.
  return KeysetHandle::GenerateNew(key_template,
                                   crypto::tink::KeyGenConfigGlobalRegistry());
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_create_keyset]
