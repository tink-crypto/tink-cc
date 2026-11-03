// Copyright 2018 Google LLC
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

#include "tink/util/test_keyset_handle.h"

#include <memory>
#include <utility>

#include "tink/internal/keyset_handle_access.h"
#include "tink/keyset_handle.h"
#include "tink/util/secret_proto.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;

namespace crypto {
namespace tink {

// static
std::unique_ptr<KeysetHandle> TestKeysetHandle::GetKeysetHandle(
    const Keyset& keyset) {
  return std::make_unique<KeysetHandle>(
      internal::KeysetHandleAccess::Create(util::SecretProto<Keyset>(keyset)));
}

// static
const Keyset& TestKeysetHandle::GetKeyset(const KeysetHandle& keyset_handle) {
  return internal::KeysetHandleAccess::GetKeyset(keyset_handle);
}

}  // namespace tink
}  // namespace crypto
