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

#ifndef TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_
#define TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

class HpkeEncrypt : public HybridEncrypt {
 public:
  // Copyable and movable.
  HpkeEncrypt(const HpkeEncrypt& other) = default;
  HpkeEncrypt& operator=(const HpkeEncrypt& other) = default;
  HpkeEncrypt(HpkeEncrypt&& other) = default;
  HpkeEncrypt& operator=(HpkeEncrypt&& other) = default;

  static absl::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const google::crypto::tink::HpkePublicKey& recipient_public_key);

  static absl::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const ::crypto::tink::HpkePublicKey& recipient_public_key);

  absl::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

 private:
  static absl::StatusOr<std::unique_ptr<HybridEncrypt>> New(
      const google::crypto::tink::HpkePublicKey& recipient_public_key,
      absl::string_view output_prefix);

  explicit HpkeEncrypt(
      const google::crypto::tink::HpkePublicKey& recipient_public_key,
      absl::string_view output_prefix)
      : recipient_public_key_(recipient_public_key),
        output_prefix_(output_prefix) {}

  absl::StatusOr<std::string> EncryptNoPrefix(
      absl::string_view plaintext, absl::string_view context_info) const;

  google::crypto::tink::HpkePublicKey recipient_public_key_;
  std::string output_prefix_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_ENCRYPT_H_
