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

#include "tink/signature/internal/sign_prehash_wrapper.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/endian.h"
#include "tink/internal/primitive_set.h"
#include "tink/internal/util.h"
#include "tink/signature/internal/prehash_format.h"
#include "tink/signature/sign_prehash.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::OutputPrefixType;

absl::Status Validate(PrimitiveSet<SignPrehash>* prehash_sign_set) {
  if (prehash_sign_set == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "prehash_sign_set must be non-null");
  }
  if (prehash_sign_set->get_primary() == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "prehash_sign_set has no primary");
  }

  for (const auto& primitive : prehash_sign_set->get_all()) {
    if (primitive->get_output_prefix_type() == OutputPrefixType::RAW) {
      return absl::Status(
          absl::StatusCode::kInvalidArgument,
          "Prehash sign primitive does not allow raw output prefixes.");
    }
  }
  return absl::OkStatus();
}

class PrehashSignSetWrapper : public SignPrehash {
 public:
  explicit PrehashSignSetWrapper(
      std::unique_ptr<PrimitiveSet<SignPrehash>> prehash_sign_set)
      : prehash_sign_set_(std::move(prehash_sign_set)) {}

  absl::StatusOr<std::string> Sign(absl::string_view prehash) const override;

  ~PrehashSignSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<SignPrehash>> prehash_sign_set_;
};

absl::StatusOr<std::string> PrehashSignSetWrapper::Sign(
    absl::string_view prehash) const {
  // BoringSSL expects a non-null pointer for `prehash`,
  // regardless of whether the size is 0.
  prehash = internal::EnsureStringNonNull(prehash);

  if (prehash.length() < kPrehashPrefixSize) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Prehash is missing required prefix.");
  }

  if (static_cast<uint8_t>(prehash[0]) != kPrehashStartByte) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Prehash does not start with Prehash prefix byte.");
  }

  // The next four bytes following the start byte should contain the key id.
  uint32_t prehash_key_id =
      LoadBigEndian32(reinterpret_cast<const uint8_t*>(&prehash[1]));

  PrimitiveSet<SignPrehash>::Entry<SignPrehash>* primitive = nullptr;
  for (const auto& entry : prehash_sign_set_->get_all()) {
    if (entry->get_key_id() == prehash_key_id) {
      primitive = entry;
      break;
    }
  }

  if (primitive == nullptr) {
    return absl::Status(
        absl::StatusCode::kNotFound,
        "Could not find prehash signing key that matches prehash key id.");
  }

  prehash = prehash.substr(kPrehashPrefixSize);

  // No need for special handling of LEGACY key types (that special handling
  // already occurs in `PrehashSetWrapper`).
  absl::StatusOr<std::string> signature =
      primitive->get_primitive().Sign(prehash);
  if (!signature.ok()) return signature.status();

  return absl::StrCat(primitive->get_identifier(), *signature);
}

}  // anonymous namespace

absl::StatusOr<std::unique_ptr<SignPrehash>> SignPrehashWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<SignPrehash>> primitive_set) const {
  absl::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  return {std::make_unique<PrehashSignSetWrapper>(std::move(primitive_set))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
