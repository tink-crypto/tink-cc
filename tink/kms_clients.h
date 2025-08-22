// Copyright 2019 Google LLC
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

#ifndef TINK_KMS_CLIENTS_H_
#define TINK_KMS_CLIENTS_H_

#include <memory>
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/kms_client.h"

namespace crypto {
namespace tink {

// A container for KmsClient-objects that are needed by KeyManager-objects for
// primitives that use KMS-managed keys.
//
// This class consists exclusively of static methods that register and load
// KmsClient-objects.
class KmsClients {
 public:
  // Adds 'kms_client' to the global list of known clients.
  //
  // This function should only be called on startup and not on every operation.
  // Avoid registering a client more than once.
  //
  // It is often not necessary to use this function. For example, you can call
  // kms_client.GetAead to get a remote AEAD instance, and use that to create
  // an encrypted keyset using KeysetHandle::Write, or create an envelope
  // AEAD using KmsEnvelopeAead::New.
  static absl::Status Add(std::unique_ptr<KmsClient> kms_client) {
    return GlobalInstance().LocalAdd(std::move(kms_client));
  }

  // Returns the first KmsClient that was added previously via Add(),
  // and that does support 'key_uri', which must be non-empty.
  // Retains the ownership of the returned KmsClient.
  static absl::StatusOr<const KmsClient *> Get(absl::string_view key_uri) {
    return GlobalInstance().LocalGet(key_uri);
  }

 private:
  KmsClients() = default;

  // Per-instance API, to be used by GlobalInstance();
  absl::Status LocalAdd(std::unique_ptr<KmsClient> kms_client);
  absl::StatusOr<const KmsClient *> LocalGet(absl::string_view key_uri);
  absl::Mutex clients_mutex_;
  std::vector<std::unique_ptr<KmsClient>> clients_
      ABSL_GUARDED_BY(clients_mutex_);

  static KmsClients& GlobalInstance();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KMS_CLIENTS_H_
