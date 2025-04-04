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

#include "tink/hybrid/hybrid_decrypt_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/monitoring.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/util.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

constexpr absl::string_view kPrimitive = "hybrid_decrypt";
constexpr absl::string_view kDecryptApi = "decrypt";

class HybridDecryptSetWrapper : public HybridDecrypt {
 public:
  explicit HybridDecryptSetWrapper(
      std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set,
      std::unique_ptr<internal::MonitoringClient> monitoring_decryption_client =
          nullptr)
      : hybrid_decrypt_set_(std::move(hybrid_decrypt_set)),
        monitoring_decryption_client_(std::move(monitoring_decryption_client)) {
  }

  absl::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override;

  ~HybridDecryptSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set_;
  std::unique_ptr<internal::MonitoringClient> monitoring_decryption_client_;
};

absl::StatusOr<std::string> HybridDecryptSetWrapper::Decrypt(
    absl::string_view ciphertext, absl::string_view context_info) const {
  // BoringSSL expects a non-null pointer for context_info,
  // regardless of whether the size is 0.
  context_info = internal::EnsureStringNonNull(context_info);

  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = hybrid_decrypt_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& hybrid_decrypt_entry : *(primitives_result.value())) {
        HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry->get_primitive();
        auto decrypt_result =
            hybrid_decrypt.Decrypt(raw_ciphertext, context_info);
        if (decrypt_result.ok()) {
          if (monitoring_decryption_client_ != nullptr) {
            monitoring_decryption_client_->Log(
                hybrid_decrypt_entry->get_key_id(), ciphertext.size());
          }
          return std::move(decrypt_result.value());
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  auto raw_primitives_result = hybrid_decrypt_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& hybrid_decrypt_entry : *(raw_primitives_result.value())) {
      HybridDecrypt& hybrid_decrypt = hybrid_decrypt_entry->get_primitive();
      auto decrypt_result = hybrid_decrypt.Decrypt(ciphertext, context_info);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.value());
      }
    }
  }
  if (monitoring_decryption_client_ != nullptr) {
    monitoring_decryption_client_->LogFailure();
  }
  return absl::Status(absl::StatusCode::kInvalidArgument, "decryption failed");
}

absl::Status Validate(PrimitiveSet<HybridDecrypt>* hybrid_decrypt_set) {
  if (hybrid_decrypt_set == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "hybrid_decrypt_set must be non-NULL");
  }
  if (hybrid_decrypt_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "hybrid_decrypt_set has no primary");
  }
  return absl::OkStatus();
}

}  // anonymous namespace

// static
absl::StatusOr<std::unique_ptr<HybridDecrypt>> HybridDecryptWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<HybridDecrypt>> primitive_set) const {
  absl::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  internal::MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {
        absl::make_unique<HybridDecryptSetWrapper>(std::move(primitive_set))};
  }

  absl::StatusOr<internal::MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*primitive_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  absl::StatusOr<std::unique_ptr<internal::MonitoringClient>>
      monitoring_decryption_client = monitoring_factory->New(
          internal::MonitoringContext(kPrimitive, kDecryptApi, *keyset_info));
  if (!monitoring_decryption_client.ok()) {
    return monitoring_decryption_client.status();
  }

  return {absl::make_unique<HybridDecryptSetWrapper>(
      std::move(primitive_set), *std::move(monitoring_decryption_client))};
}

}  // namespace tink
}  // namespace crypto
