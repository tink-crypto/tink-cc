// Copyright 2024 Google LLC
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

#include "tink/kem/internal/kem_encapsulate_wrapper.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/kem/kem_encapsulate.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::google::crypto::tink::OutputPrefixType;

util::Status Validate(PrimitiveSet<KemEncapsulate>* kem_encapsulate_set) {
  if (kem_encapsulate_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "kem_encapsulate_set must be non-NULL");
  }
  if (kem_encapsulate_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "kem_encapsulate_set has no primary");
  }

  absl::flat_hash_set<uint32_t> key_ids;
  for (const auto& entry : kem_encapsulate_set->get_all()) {
    if (entry->get_output_prefix_type() != OutputPrefixType::TINK) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "kem_encapsulate_set contains non-Tink prefixed key");
    }
    if (!key_ids.insert(entry->get_key_id()).second) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "kem_encapsulate_set contains several keys with the same ID");
    }
  }

  return util::OkStatus();
}

class KemEncapsulateSetWrapper : public KemEncapsulate {
 public:
  explicit KemEncapsulateSetWrapper(
      std::unique_ptr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set)
      : kem_encapsulate_set_(std::move(kem_encapsulate_set)) {}

  util::StatusOr<KemEncapsulation> Encapsulate() const override;

  ~KemEncapsulateSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<KemEncapsulate>> kem_encapsulate_set_;
};

util::StatusOr<KemEncapsulation> KemEncapsulateSetWrapper::Encapsulate() const {
  return kem_encapsulate_set_->get_primary()->get_primitive().Encapsulate();
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<KemEncapsulate>> KemEncapsulateWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<KemEncapsulate>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) {
    return status;
  }

  return absl::make_unique<KemEncapsulateSetWrapper>(std::move(primitive_set));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
