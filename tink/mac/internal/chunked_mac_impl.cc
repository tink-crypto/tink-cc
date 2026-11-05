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

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/chunked_mac.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/dfsan_forwarders.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/safe_stringops.h"
#include "tink/mac/aes_cmac_key.h"
#include "tink/mac/aes_cmac_parameters.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/internal/stateful_cmac_boringssl.h"
#include "tink/mac/internal/stateful_hmac_boringssl.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "proto/aes_cmac.pb.h"
#include "proto/hmac.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::HashType> ToSubtleHashType(
    HmacParameters::HashType hash_type) {
  switch (hash_type) {
    case HmacParameters::HashType::kSha1:
      return subtle::HashType::SHA1;
    case HmacParameters::HashType::kSha224:
      return subtle::HashType::SHA224;
    case HmacParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case HmacParameters::HashType::kSha384:
      return subtle::HashType::SHA384;
    case HmacParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::InvalidArgumentError(
          absl::StrCat("Unsupported hash type: ", hash_type));
  }
}

}  // namespace

using AesCmacKeyProto = ::google::crypto::tink::AesCmacKey;
using HmacKeyProto = ::google::crypto::tink::HmacKey;

using ::crypto::tink::util::SecretDataAsStringView;

absl::Status ChunkedMacComputationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

absl::StatusOr<std::string> ChunkedMacComputationImpl::ComputeMac() {
  if (!status_.ok()) return status_;
  status_ = absl::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC computation already finalized.");
  if (!message_suffix_.empty()) {
    absl::Status update_status = stateful_mac_->Update(message_suffix_);
    if (!update_status.ok()) {
      return update_status;
    }
  }
  absl::StatusOr<SecretData> result_tag = stateful_mac_->FinalizeAsSecretData();
  if (!result_tag.ok()) {
    return result_tag.status();
  }
  // The tag is now safe to release: the API indicates the user anyhow
  // sends it to the world.
  DfsanClearLabel(result_tag->data(), result_tag->size());
  return absl::StrCat(output_prefix_, SecretDataAsStringView(*result_tag));
}

absl::Status ChunkedMacVerificationImpl::Update(absl::string_view data) {
  if (!status_.ok()) return status_;
  return stateful_mac_->Update(data);
}

absl::Status ChunkedMacVerificationImpl::VerifyMac() {
  if (!status_.ok()) return status_;
  status_ = absl::Status(absl::StatusCode::kFailedPrecondition,
                         "MAC verification already finalized.");
  if (!absl::StartsWith(tag_, output_prefix_)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  if (!message_suffix_.empty()) {
    absl::Status update_status = stateful_mac_->Update(message_suffix_);
    if (!update_status.ok()) {
      return update_status;
    }
  }
  absl::StatusOr<SecretData> computed_mac =
      stateful_mac_->FinalizeAsSecretData();
  if (!computed_mac.ok()) {
    return computed_mac.status();
  }
  absl::string_view raw_tag =
      absl::string_view(tag_).substr(output_prefix_.size());
  if (computed_mac->size() != raw_tag.size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Verification failed.");
  }
  if (!SafeCryptoMemEquals(computed_mac->data(), raw_tag.data(),
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

  return std::unique_ptr<ChunkedMacComputation>(new ChunkedMacComputationImpl(
      *std::move(stateful_mac), output_prefix_, message_suffix_));
}

absl::StatusOr<std::unique_ptr<ChunkedMacVerification>>
ChunkedMacImpl::CreateVerification(absl::string_view tag) const {
  absl::StatusOr<std::unique_ptr<StatefulMac>> stateful_mac =
      stateful_mac_factory_->Create();
  if (!stateful_mac.ok()) return stateful_mac.status();

  return std::unique_ptr<ChunkedMacVerification>(new ChunkedMacVerificationImpl(
      *std::move(stateful_mac), tag, output_prefix_, message_suffix_));
}

absl::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedCmac(
    const AesCmacKeyProto& key) {
  if (!key.has_params()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid key: missing parameters.");
  }
  SecretData secret_key_data = util::SecretDataFromStringView(key.key_value());
  auto stateful_mac_factory = std::make_unique<StatefulCmacBoringSslFactory>(
      key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

absl::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedCmac(
    const AesCmacKey& key) {
  ABSL_RETURN_IF_ERROR(ChecksFipsCompatibility(FipsCompatibility::kNotFips));
  auto stateful_mac_factory = std::make_unique<StatefulCmacBoringSslFactory>(
      key.GetParameters().CryptographicTagSizeInBytes(),
      key.GetKeyBytes(GetPartialKeyAccess())
          .Get(InsecureSecretKeyAccess::Get()));
  absl::string_view message_suffix =
      key.GetParameters().GetVariant() == AesCmacParameters::Variant::kLegacy
          ? absl::string_view("\0", 1)
          : "";
  return std::make_unique<ChunkedMacImpl>(
      std::move(stateful_mac_factory), key.GetOutputPrefix(), message_suffix);
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
      std::make_unique<internal::StatefulHmacBoringSslFactory>(
          hash_type, key.params().tag_size(), secret_key_data);
  return std::unique_ptr<ChunkedMac>(
      new ChunkedMacImpl(std::move(stateful_mac_factory)));
}

absl::StatusOr<std::unique_ptr<ChunkedMac>> NewChunkedHmac(const HmacKey& key) {
  ABSL_RETURN_IF_ERROR(
      ChecksFipsCompatibility(FipsCompatibility::kRequiresBoringCrypto));
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hash_type,
                        ToSubtleHashType(key.GetParameters().GetHashType()));
  auto stateful_mac_factory =
      std::make_unique<internal::StatefulHmacBoringSslFactory>(
          hash_type, key.GetParameters().CryptographicTagSizeInBytes(),
          key.GetKeyBytes(GetPartialKeyAccess())
              .Get(InsecureSecretKeyAccess::Get()));
  absl::string_view message_suffix =
      key.GetParameters().GetVariant() == HmacParameters::Variant::kLegacy
          ? absl::string_view("\0", 1)
          : "";
  return std::make_unique<ChunkedMacImpl>(
      std::move(stateful_mac_factory), key.GetOutputPrefix(), message_suffix);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
