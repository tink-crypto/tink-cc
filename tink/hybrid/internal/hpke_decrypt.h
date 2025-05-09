// Copyright 2021 Google LLC
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

#ifndef TINK_HYBRID_INTERNAL_HPKE_DECRYPT_H_
#define TINK_HYBRID_INTERNAL_HPKE_DECRYPT_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid_decrypt.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class HpkeDecrypt : public HybridDecrypt {
 public:
  // Copyable and movable.
  HpkeDecrypt(const HpkeDecrypt& other) = default;
  HpkeDecrypt& operator=(const HpkeDecrypt& other) = default;
  HpkeDecrypt(HpkeDecrypt&& other) = default;
  HpkeDecrypt& operator=(HpkeDecrypt&& other) = default;

  static absl::StatusOr<std::unique_ptr<HybridDecrypt>> New(
      const google::crypto::tink::HpkePrivateKey& recipient_private_key);

  static absl::StatusOr<std::unique_ptr<HybridDecrypt>> New(
      const crypto::tink::HpkePrivateKey& recipient_private_key);

  absl::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override;

 private:
  HpkeDecrypt(const google::crypto::tink::HpkeParams& hpke_params,
              const SecretData& recipient_private_key,
              absl::string_view output_prefix)
      : hpke_params_(hpke_params),
        recipient_private_key_(recipient_private_key),
        output_prefix_(output_prefix) {}

  static absl::StatusOr<std::unique_ptr<HybridDecrypt>> New(
      const google::crypto::tink::HpkeParams& hpke_params,
      const SecretData& recipient_private_key, absl::string_view output_prefix);

  absl::StatusOr<std::string> DecryptNoPrefix(
      absl::string_view ciphertext, absl::string_view context_info) const;

  google::crypto::tink::HpkeParams hpke_params_;
  SecretData recipient_private_key_;
  std::string output_prefix_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_DECRYPT_H_
