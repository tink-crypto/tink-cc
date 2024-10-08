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

#ifndef TINK_AEAD_X_AES_GCM_KEY_MANAGER_H_
#define TINK_AEAD_X_AES_GCM_KEY_MANAGER_H_

#include <memory>

#include "tink/aead.h"
#include "tink/aead/cord_aead.h"
#include "tink/core/key_type_manager.h"
#include "tink/core/template_util.h"
#include "proto/tink.pb.h"
#include "proto/x_aes_gcm.pb.h"

namespace crypto {
namespace tink {

using XAesGcmKeyManager =
    KeyTypeManager<google::crypto::tink::XAesGcmKey,
                   google::crypto::tink::XAesGcmKeyFormat,
                   List<crypto::tink::Aead, crypto::tink::CordAead>>;

std::unique_ptr<XAesGcmKeyManager> CreateXAesGcmKeyManager();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_X_AES_GCM_KEY_MANAGER_H_
