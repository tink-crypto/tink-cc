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

#include "tink/jwt/internal/jwt_mac_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using ::google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "jwtmac";
constexpr absl::string_view kComputeApi = "compute";
constexpr absl::string_view kVerifyApi = "verify";
constexpr int kReportedJwtSize =
    1;  // We do not log the actual size of the JWT.

class JwtMacSetWrapper : public JwtMac {
 public:
  explicit JwtMacSetWrapper(
      std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set,
      std::unique_ptr<MonitoringClient> monitoring_compute_client = nullptr,
      std::unique_ptr<MonitoringClient> monitoring_verify_client = nullptr)
      : jwt_mac_set_(std::move(jwt_mac_set)),
        monitoring_compute_client_(std::move(monitoring_compute_client)),
        monitoring_verify_client_(std::move(monitoring_verify_client)) {}

  absl::StatusOr<std::string> ComputeMacAndEncode(
      const crypto::tink::RawJwt& token) const override;

  absl::StatusOr<crypto::tink::VerifiedJwt> VerifyMacAndDecode(
      absl::string_view compact,
      const crypto::tink::JwtValidator& validator) const override;

  ~JwtMacSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set_;
  std::unique_ptr<MonitoringClient> monitoring_compute_client_;
  std::unique_ptr<MonitoringClient> monitoring_verify_client_;
};

absl::Status Validate(PrimitiveSet<JwtMacInternal>* jwt_mac_set) {
  if (jwt_mac_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "jwt_mac_set must be non-NULL");
  }
  if (jwt_mac_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "jwt_mac_set has no primary");
  }
  for (const auto* entry : jwt_mac_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> JwtMacSetWrapper::ComputeMacAndEncode(
    const crypto::tink::RawJwt& token) const {
  auto primary = jwt_mac_set_->get_primary();
  absl::optional<std::string> kid =
      GetKid(primary->get_key_id(), primary->get_output_prefix_type());

  absl::StatusOr<std::string> compute_mac_result =
      primary->get_primitive().ComputeMacAndEncodeWithKid(token, kid);
  if (!compute_mac_result.ok()) {
    if (monitoring_compute_client_ != nullptr) {
      monitoring_compute_client_->LogFailure();
    }
    return compute_mac_result.status();
  }
  if (monitoring_compute_client_ != nullptr) {
    monitoring_compute_client_->Log(primary->get_key_id(), kReportedJwtSize);
  }
  return compute_mac_result;
}

absl::StatusOr<crypto::tink::VerifiedJwt> JwtMacSetWrapper::VerifyMacAndDecode(
    absl::string_view compact,
    const crypto::tink::JwtValidator& validator) const {
  absl::optional<absl::Status> interesting_status;
  for (const auto* mac_entry : jwt_mac_set_->get_all()) {
    JwtMacInternal& jwt_mac = mac_entry->get_primitive();
    absl::optional<std::string> kid =
        GetKid(mac_entry->get_key_id(), mac_entry->get_output_prefix_type());
    absl::StatusOr<VerifiedJwt> verified_jwt =
        jwt_mac.VerifyMacAndDecodeWithKid(compact, validator, kid);
    if (verified_jwt.ok()) {
      if (monitoring_verify_client_ != nullptr) {
        monitoring_verify_client_->Log(mac_entry->get_key_id(),
                                       kReportedJwtSize);
      }
      return verified_jwt;
    } else if (verified_jwt.status().code() !=
               absl::StatusCode::kUnauthenticated) {
      // errors that are not the result of a MAC verification
      interesting_status = verified_jwt.status();
    }
  }
  if (monitoring_verify_client_ != nullptr) {
    monitoring_verify_client_->LogFailure();
  }
  if (interesting_status.has_value()) {
    return *interesting_status;
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "verification failed");
}

}  // namespace

absl::StatusOr<std::unique_ptr<JwtMac>> JwtMacWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set) const {
  absl::Status status = Validate(jwt_mac_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<JwtMacSetWrapper>(std::move(jwt_mac_set))};
  }

  absl::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*jwt_mac_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_compute_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kComputeApi, *keyset_info));
  if (!monitoring_compute_client.ok()) {
    return monitoring_compute_client.status();
  }

  absl::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_verify_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kVerifyApi, *keyset_info));
  if (!monitoring_verify_client.ok()) {
    return monitoring_verify_client.status();
  }

  std::unique_ptr<JwtMac> jwt_mac = absl::make_unique<JwtMacSetWrapper>(
      std::move(jwt_mac_set), *std::move(monitoring_compute_client),
      *std::move(monitoring_verify_client));
  return std::move(jwt_mac);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
