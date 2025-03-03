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

#include "tink/jwt/internal/jwt_public_key_verify_wrapper.h"

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
#include "tink/jwt/internal/jwt_public_key_verify_internal.h"
#include "tink/jwt/jwt_public_key_verify.h"
#include "tink/jwt/jwt_validator.h"
#include "tink/jwt/verified_jwt.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "jwtverify";
constexpr absl::string_view kVerifyApi = "verify";
constexpr int kReportedJwtSize = 1;

class JwtPublicKeyVerifySetWrapper : public JwtPublicKeyVerify {
 public:
  explicit JwtPublicKeyVerifySetWrapper(
      std::unique_ptr<PrimitiveSet<JwtPublicKeyVerifyInternal>> jwt_verify_set,
      std::unique_ptr<MonitoringClient> monitoring_verify_client = nullptr)
      : jwt_verify_set_(std::move(jwt_verify_set)),
        monitoring_verify_client_(std::move(monitoring_verify_client)) {}

  absl::StatusOr<crypto::tink::VerifiedJwt> VerifyAndDecode(
      absl::string_view compact,
      const crypto::tink::JwtValidator& validator) const override;

  ~JwtPublicKeyVerifySetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<JwtPublicKeyVerifyInternal>> jwt_verify_set_;
  std::unique_ptr<MonitoringClient> monitoring_verify_client_;
};

absl::Status Validate(
    PrimitiveSet<JwtPublicKeyVerifyInternal>* jwt_verify_set) {
  if (jwt_verify_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "jwt_verify_set must be non-NULL");
  }
  for (const auto* entry : jwt_verify_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<crypto::tink::VerifiedJwt>
JwtPublicKeyVerifySetWrapper::VerifyAndDecode(
    absl::string_view compact,
    const crypto::tink::JwtValidator& validator) const {
  absl::optional<absl::Status> interesting_status;
  for (const auto* entry : jwt_verify_set_->get_all()) {
    JwtPublicKeyVerifyInternal& jwt_verify = entry->get_primitive();
    absl::optional<std::string> kid =
        GetKid(entry->get_key_id(), entry->get_output_prefix_type());
    absl::StatusOr<VerifiedJwt> verified_jwt =
        jwt_verify.VerifyAndDecodeWithKid(compact, validator, kid);
    if (verified_jwt.ok()) {
      if (monitoring_verify_client_ != nullptr) {
        monitoring_verify_client_->Log(entry->get_key_id(), kReportedJwtSize);
      }
      return verified_jwt;
    } else if (verified_jwt.status().code() !=
               absl::StatusCode::kUnauthenticated) {
      // errors that are not the result of a signature verification
      interesting_status = verified_jwt.status();
    }
  }
  if (monitoring_verify_client_ != nullptr) {
    monitoring_verify_client_->LogFailure();
  }
  if (interesting_status.has_value()) {
    return *std::move(interesting_status);
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "verification failed");
}

}  // namespace

absl::StatusOr<std::unique_ptr<JwtPublicKeyVerify>>
JwtPublicKeyVerifyWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtPublicKeyVerifyInternal>> jwt_verify_set)
    const {
  absl::Status status = Validate(jwt_verify_set.get());
  if (!status.ok()) return status;
  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<JwtPublicKeyVerifySetWrapper>(
        std::move(jwt_verify_set))};
  }

  absl::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*jwt_verify_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_verify_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kVerifyApi, *keyset_info));
  if (!monitoring_verify_client.ok()) {
    return monitoring_verify_client.status();
  }

  std::unique_ptr<JwtPublicKeyVerify> jwt_verify =
      absl::make_unique<JwtPublicKeyVerifySetWrapper>(
          std::move(jwt_verify_set), std::move(*monitoring_verify_client));
  return std::move(jwt_verify);
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
