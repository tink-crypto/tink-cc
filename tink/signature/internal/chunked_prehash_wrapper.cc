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

#include "tink/signature/internal/chunked_prehash_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/internal/primitive_set.h"
#include "tink/signature/chunked_prehash.h"
#include "tink/signature/internal/prehash_format.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::OutputPrefixType;

class ChunkedPrehashComputationSetWrapper : public ChunkedPrehashComputation {
 public:
  explicit ChunkedPrehashComputationSetWrapper(
      std::unique_ptr<ChunkedPrehashComputation> computation,
      absl::string_view prehash_prefix, OutputPrefixType output_prefix_type)
      : computation_(std::move(computation)),
        prehash_prefix_(prehash_prefix),
        output_prefix_type_(output_prefix_type) {}

  absl::Status Update(absl::string_view data) override;

  absl::StatusOr<std::string> GetPrehash() override;

 private:
  const std::unique_ptr<ChunkedPrehashComputation> computation_;
  const std::string prehash_prefix_;
  const OutputPrefixType output_prefix_type_;
};

absl::Status ChunkedPrehashComputationSetWrapper::Update(
    absl::string_view data) {
  return computation_->Update(data);
}

absl::StatusOr<std::string> ChunkedPrehashComputationSetWrapper::GetPrehash() {
  if (output_prefix_type_ == OutputPrefixType::LEGACY) {
    // LEGACY keys append an additional 0x00 byte to the data.
    absl::Status append_status =
        computation_->Update(std::string(1, CryptoFormat::kLegacyStartByte));
    if (!append_status.ok()) {
      return append_status;
    }
  }
  absl::StatusOr<std::string> raw_prehash_value = computation_->GetPrehash();
  if (!raw_prehash_value.ok()) {
    return raw_prehash_value.status();
  }

  return absl::StrCat(prehash_prefix_, *raw_prehash_value);
}

absl::Status Validate(PrimitiveSet<ChunkedPrehash>* prehash_set) {
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
          "Chunked prehash primitive does not allow raw output prefixes.");
    }
  }
  return absl::OkStatus();
}

class ChunkedPrehashSetWrapper : public ChunkedPrehash {
 public:
  explicit ChunkedPrehashSetWrapper(
      std::unique_ptr<PrimitiveSet<ChunkedPrehash>> prehash_set)
      : prehash_set_(std::move(prehash_set)) {}

  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> CreateComputation()
      const override;

  ~ChunkedPrehashSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<ChunkedPrehash>> prehash_set_;
};

absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>>
ChunkedPrehashSetWrapper::CreateComputation() const {
  const PrimitiveSet<ChunkedPrehash>::Entry<ChunkedPrehash>* primary =
      prehash_set_->get_primary();
  absl::StatusOr<std::unique_ptr<ChunkedPrehashComputation>> computation =
      primary->get_primitive().CreateComputation();
  if (!computation.ok()) {
    return computation.status();
  }
  return {std::make_unique<ChunkedPrehashComputationSetWrapper>(
      *std::move(computation), GetPrehashPrefix(primary->get_key_id()),
      primary->get_output_prefix_type())};
}

}  // namespace

absl::StatusOr<std::unique_ptr<ChunkedPrehash>> ChunkedPrehashWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<ChunkedPrehash>> prehash_set) const {
  absl::Status status = Validate(prehash_set.get());
  if (!status.ok()) {
    return status;
  }
  return {std::make_unique<ChunkedPrehashSetWrapper>(std::move(prehash_set))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
