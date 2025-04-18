// Copyright 2017 Google Inc.
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

#include "tink/mac/mac_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "mac";
constexpr absl::string_view kComputeApi = "compute";
constexpr absl::string_view kVerifyApi = "verify";

class MacSetWrapper : public Mac {
 public:
  explicit MacSetWrapper(
      std::unique_ptr<PrimitiveSet<Mac>> mac_set,
      std::unique_ptr<internal::MonitoringClient> monitoring_compute_client =
          nullptr,
      std::unique_ptr<internal::MonitoringClient> monitoring_verify_client =
          nullptr)
      : mac_set_(std::move(mac_set)),
        monitoring_compute_client_(std::move(monitoring_compute_client)),
        monitoring_verify_client_(std::move(monitoring_verify_client)) {}

  absl::StatusOr<std::string> ComputeMac(absl::string_view data) const override;

  absl::Status VerifyMac(absl::string_view mac_value,
                         absl::string_view data) const override;

  ~MacSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<Mac>> mac_set_;
  std::unique_ptr<internal::MonitoringClient> monitoring_compute_client_;
  std::unique_ptr<internal::MonitoringClient> monitoring_verify_client_;
};

absl::Status Validate(PrimitiveSet<Mac>* mac_set) {
  if (mac_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "mac_set must be non-NULL");
  }
  if (mac_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "mac_set has no primary");
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> MacSetWrapper::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  auto primary = mac_set_->get_primary();
  std::string local_data;
  if (primary->get_output_prefix_type() == OutputPrefixType::LEGACY) {
    local_data = std::string(data);
    local_data.push_back(CryptoFormat::kLegacyStartByte);
    data = local_data;
  }
  auto compute_mac_result = primary->get_primitive().ComputeMac(data);
  if (!compute_mac_result.ok()) {
    if (monitoring_compute_client_ != nullptr) {
      monitoring_compute_client_->LogFailure();
    }
    return compute_mac_result.status();
  }
  if (monitoring_compute_client_ != nullptr) {
    monitoring_compute_client_->Log(mac_set_->get_primary()->get_key_id(),
                                    data.size());
  }
  const std::string& key_id = primary->get_identifier();
  return key_id + compute_mac_result.value();
}

absl::Status MacSetWrapper::VerifyMac(absl::string_view mac_value,
                                      absl::string_view data) const {
  data = internal::EnsureStringNonNull(data);
  mac_value = internal::EnsureStringNonNull(mac_value);

  if (mac_value.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        mac_value.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = mac_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_mac_value =
          mac_value.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& mac_entry : *(primitives_result.value())) {
        std::string legacy_data;
        absl::string_view view_on_data_or_legacy_data = data;
        if (mac_entry->get_output_prefix_type() == OutputPrefixType::LEGACY) {
          legacy_data = absl::StrCat(data, std::string("\x00", 1));
          view_on_data_or_legacy_data = legacy_data;
        }
        Mac& mac = mac_entry->get_primitive();
        absl::Status status =
            mac.VerifyMac(raw_mac_value, view_on_data_or_legacy_data);
        if (status.ok()) {
          if (monitoring_verify_client_ != nullptr) {
            monitoring_verify_client_->Log(mac_entry->get_key_id(),
                                           data.size());
          }
          return status;
        }
      }
    }
  }

  // No matching key succeeded with verification, try all RAW keys.
  auto raw_primitives_result = mac_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& mac_entry : *(raw_primitives_result.value())) {
      Mac& mac = mac_entry->get_primitive();
      absl::Status status = mac.VerifyMac(mac_value, data);
      if (status.ok()) {
        if (monitoring_verify_client_ != nullptr) {
          monitoring_verify_client_->Log(mac_entry->get_key_id(), data.size());
        }
        return status;
      }
    }
  }
  if (monitoring_verify_client_ != nullptr) {
    monitoring_verify_client_->LogFailure();
  }

  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "verification failed");
}

}  // namespace

absl::StatusOr<std::unique_ptr<Mac>> MacWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<Mac>> mac_set) const {
  absl::Status status = Validate(mac_set.get());
  if (!status.ok()) return status;

  internal::MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<MacSetWrapper>(std::move(mac_set))};
  }

  absl::StatusOr<internal::MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*mac_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>
      monitoring_compute_client = monitoring_factory->New(
          internal::MonitoringContext(kPrimitive, kComputeApi, *keyset_info));
  if (!monitoring_compute_client.ok()) {
    return monitoring_compute_client.status();
  }

  absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>
      monitoring_verify_client = monitoring_factory->New(
          internal::MonitoringContext(kPrimitive, kVerifyApi, *keyset_info));
  if (!monitoring_verify_client.ok()) {
    return monitoring_verify_client.status();
  }

  return {absl::make_unique<MacSetWrapper>(
      std::move(mac_set), *std::move(monitoring_compute_client),
      *std::move(monitoring_verify_client))};
}

}  // namespace tink
}  // namespace crypto
