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

#include "tink/jwt/internal/jwt_public_key_sign_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/jwt/internal/jwt_format.h"
#include "tink/jwt/internal/jwt_public_key_sign_internal.h"
#include "tink/jwt/jwt_public_key_sign.h"
#include "tink/jwt/raw_jwt.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

using google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "jwtsign";
constexpr absl::string_view kSignApi = "sign";
constexpr int kReportedJwtSize = 1;

class JwtPublicKeySignSetWrapper : public JwtPublicKeySign {
 public:
  explicit JwtPublicKeySignSetWrapper(
      std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set,
      std::unique_ptr<MonitoringClient> monitoring_sign_client = nullptr)
      : jwt_sign_set_(std::move(jwt_sign_set)),
        monitoring_sign_client_(std::move(monitoring_sign_client)) {}

  absl::StatusOr<std::string> SignAndEncode(
      const crypto::tink::RawJwt& token) const override;

  ~JwtPublicKeySignSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set_;
  std::unique_ptr<MonitoringClient> monitoring_sign_client_;
};

absl::Status Validate(PrimitiveSet<JwtPublicKeySignInternal>* jwt_sign_set) {
  if (jwt_sign_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "jwt_sign_set must be non-NULL");
  }
  if (jwt_sign_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "jwt_sign_set has no primary");
  }
  for (const auto* entry : jwt_sign_set->get_all()) {
    if ((entry->get_output_prefix_type() != OutputPrefixType::RAW) &&
        (entry->get_output_prefix_type() != OutputPrefixType::TINK)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "all JWT keys must be either RAW or TINK");
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> JwtPublicKeySignSetWrapper::SignAndEncode(
    const crypto::tink::RawJwt& token) const {
  auto primary = jwt_sign_set_->get_primary();
  auto sign_result = primary->get_primitive().SignAndEncodeWithKid(
      token, GetKid(primary->get_key_id(), primary->get_output_prefix_type()));

  if (!sign_result.ok()) {
    if (monitoring_sign_client_ != nullptr) {
      monitoring_sign_client_->LogFailure();
    }
    return sign_result.status();
  }
  if (monitoring_sign_client_ != nullptr) {
    monitoring_sign_client_->Log(jwt_sign_set_->get_primary()->get_key_id(),
                                 kReportedJwtSize);
  }

  return sign_result;
}

}  // namespace

absl::StatusOr<std::unique_ptr<JwtPublicKeySign>> JwtPublicKeySignWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<JwtPublicKeySignInternal>> jwt_sign_set)
    const {
  absl::Status status = Validate(jwt_sign_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {
        absl::make_unique<JwtPublicKeySignSetWrapper>(std::move(jwt_sign_set))};
  }

  absl::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*jwt_sign_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_sign_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kSignApi, *keyset_info));
  if (!monitoring_sign_client.ok()) {
    return monitoring_sign_client.status();
  }

  std::unique_ptr<JwtPublicKeySign> jwt_sign =
      absl::make_unique<JwtPublicKeySignSetWrapper>(
          std::move(jwt_sign_set), *std::move(monitoring_sign_client));
  return {std::move(jwt_sign)};
}

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto
