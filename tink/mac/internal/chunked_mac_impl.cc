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

#include "tink/mac/internal/chunked_mac_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "tink/chunked_mac.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/safe_stringops.h"
#include "tink/mac/internal/stateful_cmac_boringssl.h"
#include "tink/mac/internal/stateful_hmac_boringssl.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_cmac.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using AesCmacKeyProto = ::google::crypto::tink::AesCmacKey;
using HmacKeyProto = ::google::crypto::tink::HmacKey;

using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;

absl::Status ChunkedMacComputationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

absl::StatusOr<std::string> ChunkedMacComputationImpl::ComputeMac() {
  if (!status_.ok()) return status_;
  status_ = absl::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC computation already finalized.");
  absl::StatusOr<SecretData> result_tag = stateful_mac_->FinalizeAsSecretData();
  if (!result_tag.ok()) {
    return result_tag.status();
  }
  // The tag is now safe to release: the API indicates the user anyhow
  // sends it to the world.
  DfsanClearLabel(result_tag->data(), result_tag->size());
  return std::string(SecretDataAsStringView(*result_tag));
}

absl::Status ChunkedMacVerificationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

absl::Status ChunkedMacVerificationImpl::VerifyMac() {
  if (!status_.ok()) return status_;
  status_ = absl::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC verification already finalized.");
  absl::StatusOr<SecretData> computed_mac =
      stateful_mac_->FinalizeAsSecretData();
  if (!computed_mac.ok()) {
    return computed_mac.status();
  }
  if (computed_mac->size() != tag_.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  if (!SafeCryptoMemEquals(computed_mac->data(), tag_.data(),
                           computed_mac->size())) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<ChunkedMacComputation>>
ChunkedMacImpl::CreateComputation() const {
  absl::StatusOr<std::unique_ptr<StatefulMac>> stateful_mac =
      stateful_mac_factory_->Create();
  if (!stateful_mac.ok()) return stateful_mac.status();

  return std::unique_ptr<ChunkedMacComputation>(
      new ChunkedMacComputationImpl(*std::move(stateful_mac)));
}

absl::StatusOr<std::unique_ptr<ChunkedMacVerification>>
ChunkedMacImpl::CreateVerification(absl::string_view tag) const {
  absl::StatusOr<std::unique_ptr<StatefulMac>> stateful_mac =
      stateful_mac_factory_->Create();
  if (!stateful_mac.ok()) return stateful_mac.status();

  return std::unique_ptr<ChunkedMacVerification>(
      new ChunkedMacVerificationImpl(*std::move(stateful_mac), tag));
}

absl::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedCmac(
    const AesCmacKeyProto& key) {
  if (!key.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid key: missing parameters.");
  }
  SecretData secret_key_data = util::SecretDataFromStringView(key.key_value());
  auto stateful_mac_factory = absl::make_unique<StatefulCmacBoringSslFactory>(
      key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

absl::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedHmac(
    const HmacKeyProto& key) {
  if (!key.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid key: missing paramaters.");
  }
  subtle::HashType hash_type = util::Enums::ProtoToSubtle(key.params().hash());
  SecretData secret_key_data = util::SecretDataFromStringView(key.key_value());
  auto stateful_mac_factory =
      absl::make_unique<internal::StatefulHmacBoringSslFactory>(
          hash_type, key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
