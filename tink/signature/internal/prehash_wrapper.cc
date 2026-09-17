// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/signature/internal/prehash_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/internal/primitive_set.h"
#include "tink/internal/util.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/prehash.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::OutputPrefixType;

absl::Status Validate(PrimitiveSet<Prehash>* prehash_set) {
  if (prehash_set == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "prehash_set must be non-null");
  }
  if (prehash_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "prehash_set must have a primary");
  }
  for (const auto& primitive : prehash_set->get_all()) {
    if (primitive->get_output_prefix_type() == OutputPrefixType::RAW) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Prehash primitive does not allow raw output prefixes, "
          "use the WITH_ID_REQUIREMENT output prefix instead.");
    }
  }
  return absl::OkStatus();
}

class PrehashSetWrapper : public Prehash {
 public:
  explicit PrehashSetWrapper(std::unique_ptr<PrimitiveSet<Prehash>> prehash_set)
      : prehash_set_(std::move(prehash_set)) {}

  absl::StatusOr<std::string> Compute(absl::string_view data) const override;

  ~PrehashSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<Prehash>> prehash_set_;
};

absl::StatusOr<std::string> PrehashSetWrapper::Compute(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data even for empty `data`.
  data = internal::EnsureStringNonNull(data);

  const PrimitiveSet<Prehash>::Entry<Prehash>* primary =
      prehash_set_->get_primary();
  std::string legacy_data;
  if (primary->get_output_prefix_type() == OutputPrefixType::LEGACY) {
    legacy_data = std::string(data);
    legacy_data.append(1, CryptoFormat::kLegacyStartByte);
    data = legacy_data;
  }

  absl::StatusOr<std::string> prehash = primary->get_primitive().Compute(data);
  if (!prehash.ok()) return prehash.status();

  std::string prehash_prefix = GetPrehashPrefix(primary->get_key_id());
  return absl::StrCat(prehash_prefix, *prehash);
}

}  // anonymous namespace

absl::StatusOr<std::unique_ptr<Prehash>> PrehashWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<Prehash>> primitive_set) const {
  absl::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  return {std::make_unique<PrehashSetWrapper>(std::move(primitive_set))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
