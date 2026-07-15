// Copyright 2017 Google LLC
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

#include "tink/signature/public_key_verify_wrapper.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_context.h"
#include "tink/internal/monitoring_key_set_info.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/util.h"
#include "tink/primitive_set.h"
#include "tink/public_key_verify.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

constexpr absl::string_view kPrimitive = "public_key_verify";
constexpr absl::string_view kVerifyApi = "verify";

using ::google::crypto::tink::OutputPrefixType;

absl::Status Validate(PrimitiveSet<PublicKeyVerify>* public_key_verify_set) {
  if (public_key_verify_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "public_key_verify_set must be non-NULL");
  }
  if (public_key_verify_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "public_key_verify_set has no primary");
  }
  return absl::OkStatus();
}

struct VerifyEntry {
  std::unique_ptr<PublicKeyVerify> primitive;
  uint32_t key_id;
  OutputPrefixType output_prefix_type;
  bool has_prefix = false;
  char prefix[CryptoFormat::kNonRawPrefixSize] = {0};
};

class PublicKeyVerifySetWrapper : public PublicKeyVerify {
 public:
  explicit PublicKeyVerifySetWrapper(std::vector<VerifyEntry> entries,
                                     std::unique_ptr<internal::MonitoringClient>
                                         monitoring_verify_client = nullptr)
      : entries_(std::move(entries)),
        monitoring_verify_client_(std::move(monitoring_verify_client)) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override;

  ~PublicKeyVerifySetWrapper() override = default;

 private:
  std::vector<VerifyEntry> entries_;
  std::unique_ptr<internal::MonitoringClient> monitoring_verify_client_;
};

absl::Status PublicKeyVerifySetWrapper::Verify(absl::string_view signature,
                                               absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);
  signature = internal::EnsureStringNonNull(signature);

  if (signature.length() <= CryptoFormat::kNonRawPrefixSize) {
    // This also rejects raw signatures with size of 4 bytes or fewer.
    // We're not aware of any schemes that output signatures that small.
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Signature too short.");
  }
  absl::string_view key_id =
      signature.substr(0, CryptoFormat::kNonRawPrefixSize);
  absl::string_view raw_signature =
      signature.substr(CryptoFormat::kNonRawPrefixSize);

  // 1. Try matching non-RAW prefix keys.
  for (const auto& entry : entries_) {
    if (entry.has_prefix &&
        absl::string_view(entry.prefix, CryptoFormat::kNonRawPrefixSize) ==
            key_id) {
      std::string legacy_data;
      absl::string_view view_on_data_or_legacy_data = data;
      if (entry.output_prefix_type == OutputPrefixType::LEGACY) {
        legacy_data = absl::StrCat(data, std::string("\x00", 1));
        view_on_data_or_legacy_data = legacy_data;
      }
      auto verify_result =
          entry.primitive->Verify(raw_signature, view_on_data_or_legacy_data);
      if (verify_result.ok()) {
        if (monitoring_verify_client_ != nullptr) {
          monitoring_verify_client_->Log(entry.key_id, data.size());
        }
        return absl::OkStatus();
      }
    }
  }

  // 2. No matching key succeeded with verification, try all RAW keys.
  for (const auto& entry : entries_) {
    if (!entry.has_prefix) {
      auto verify_result = entry.primitive->Verify(signature, data);
      if (verify_result.ok()) {
        if (monitoring_verify_client_ != nullptr) {
          monitoring_verify_client_->Log(entry.key_id, data.size());
        }
        return absl::OkStatus();
      }
    }
  }
  if (monitoring_verify_client_ != nullptr) {
    monitoring_verify_client_->LogFailure();
  }
  return absl::Status(absl::StatusCode::kInvalidArgument, "Invalid signature.");
}

std::vector<VerifyEntry> UnpackPrimitives(
    std::vector<
        std::unique_ptr<PrimitiveSet<PublicKeyVerify>::Entry<PublicKeyVerify>>>
        set_entries) {
  std::vector<VerifyEntry> entries;
  entries.reserve(set_entries.size());
  for (auto& entry : set_entries) {
    VerifyEntry verify_entry;
    verify_entry.primitive = entry->ReleasePrimitive();
    verify_entry.key_id = entry->get_key_id();
    verify_entry.output_prefix_type = entry->get_output_prefix_type();
    const std::string& identifier = entry->get_identifier();
    if (!identifier.empty()) {
      verify_entry.has_prefix = true;
      for (int i = 0; i < CryptoFormat::kNonRawPrefixSize; ++i) {
        verify_entry.prefix[i] = identifier[i];
      }
    }
    entries.push_back(std::move(verify_entry));
  }
  return entries;
}

}  // anonymous namespace

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> PublicKeyVerifyWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<PublicKeyVerify>> public_key_verify_set)
    const {
  absl::Status status = Validate(public_key_verify_set.get());
  if (!status.ok()) return status;

  internal::MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    std::vector<VerifyEntry> entries =
        UnpackPrimitives(public_key_verify_set->ReleaseAllEntries());
    return {std::make_unique<PublicKeyVerifySetWrapper>(std::move(entries))};
  }

  absl::StatusOr<internal::MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*public_key_verify_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>
      monitoring_verify_client = monitoring_factory->New(
          internal::MonitoringContext(kPrimitive, kVerifyApi, *keyset_info));
  if (!monitoring_verify_client.ok()) {
    return monitoring_verify_client.status();
  }

  std::vector<VerifyEntry> entries =
      UnpackPrimitives(public_key_verify_set->ReleaseAllEntries());
  return {std::make_unique<PublicKeyVerifySetWrapper>(
      std::move(entries), *std::move(monitoring_verify_client))};
}

}  // namespace tink
}  // namespace crypto
