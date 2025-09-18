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

#include "tink/hybrid/internal/hpke_context.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/internal/hpke_context_boringssl.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {

// Nenc values in https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1
// and https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-09.
constexpr int kP256KemEncodingLengthInBytes = 65;
constexpr int kX25519KemEncodingLengthInBytes = 32;
constexpr int kXWingKemEncodingLengthInBytes = 1120;

std::string ConcatenatePayload(absl::string_view encapsulated_key,
                               absl::string_view ciphertext) {
  return absl::StrCat(encapsulated_key, ciphertext);
}

absl::StatusOr<HpkePayloadView> SplitPayload(const HpkeKem& kem,
                                             absl::string_view payload) {
  if (kem == HpkeKem::kP256HkdfSha256) {
    return HpkePayloadView(payload.substr(0, kP256KemEncodingLengthInBytes),
                           payload.substr(kP256KemEncodingLengthInBytes));
  } else if (kem == HpkeKem::kX25519HkdfSha256) {
    return HpkePayloadView(payload.substr(0, kX25519KemEncodingLengthInBytes),
                           payload.substr(kX25519KemEncodingLengthInBytes));
  } else if (kem == HpkeKem::kXWing) {
    return HpkePayloadView(payload.substr(0, kXWingKemEncodingLengthInBytes),
                           payload.substr(kXWingKemEncodingLengthInBytes));
  }
  return absl::Status(
      absl::StatusCode::kInvalidArgument,
      absl::StrCat("Unable to split HPKE payload for KEM type ", kem));
}

absl::StatusOr<std::unique_ptr<HpkeContext>> HpkeContext::SetupSender(
    const HpkeParams& params, absl::string_view recipient_public_key,
    absl::string_view info) {
  if (recipient_public_key.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient public key is empty.");
  }
  absl::StatusOr<SenderHpkeContextBoringSsl> sender_context =
      HpkeContextBoringSsl::SetupSender(params, recipient_public_key, info);
  if (!sender_context.ok()) {
    return sender_context.status();
  }
  return {absl::WrapUnique(new HpkeContext(
      sender_context->encapsulated_key, std::move(sender_context->context)))};
}

absl::StatusOr<std::unique_ptr<HpkeContext>> HpkeContext::SetupRecipient(
    const HpkeParams& params, const SecretData& recipient_private_key,
    absl::string_view encapsulated_key, absl::string_view info) {
  if (recipient_private_key.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Recipient private key is empty.");
  }
  if (encapsulated_key.empty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Encapsulated key is empty.");
  }
  absl::StatusOr<std::unique_ptr<HpkeContextBoringSsl>> context =
      HpkeContextBoringSsl::SetupRecipient(params, recipient_private_key,
                                           encapsulated_key, info);
  if (!context.ok()) {
    return context.status();
  }
  return {absl::WrapUnique(
      new HpkeContext(encapsulated_key, *std::move(context)))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
