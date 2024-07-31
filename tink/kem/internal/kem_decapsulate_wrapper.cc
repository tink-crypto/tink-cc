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

#include "tink/kem/internal/kem_decapsulate_wrapper.h"

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/crypto_format.h"
#include "tink/kem/kem_decapsulate.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::google::crypto::tink::OutputPrefixType;

util::Status Validate(PrimitiveSet<KemDecapsulate>* kem_decapsulate_set) {
  if (kem_decapsulate_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "kem_decapsulate_set must be non-NULL");
  }
  if (kem_decapsulate_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "kem_decapsulate_set has no primary");
  }

  absl::flat_hash_set<uint32_t> key_ids;
  for (const auto& entry : kem_decapsulate_set->get_all()) {
    if (entry->get_output_prefix_type() != OutputPrefixType::TINK) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "kem_decapsulate_set contains non-Tink prefixed key");
    }
    if (!key_ids.insert(entry->get_key_id()).second) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          "kem_decapsulate_set contains several keys with the same ID");
    }
  }

  return util::OkStatus();
}

class KemDecapsulateSetWrapper : public KemDecapsulate {
 public:
  explicit KemDecapsulateSetWrapper(
      std::unique_ptr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set)
      : kem_decapsulate_set_(std::move(kem_decapsulate_set)) {}

  util::StatusOr<KeysetHandle> Decapsulate(
      absl::string_view ciphertext) const override;

  ~KemDecapsulateSetWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<KemDecapsulate>> kem_decapsulate_set_;
};

util::StatusOr<KeysetHandle> KemDecapsulateSetWrapper::Decapsulate(
    absl::string_view ciphertext) const {
  // A key ID prefix is currently mandatory, to avoid ambiguity.
  if (ciphertext.length() < CryptoFormat::kNonRawPrefixSize) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(
            "decapsulation failed: ciphertext too short; expected at least ",
            CryptoFormat::kNonRawPrefixSize, " bytes, got",
            ciphertext.length()));
  }

  absl::string_view prefix =
      ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
  util::StatusOr<const PrimitiveSet<KemDecapsulate>::Primitives*> primitives =
      kem_decapsulate_set_->get_primitives(prefix);
  if (!primitives.ok() || (*primitives)->empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "decapsulation failed: no key found for the given ID");
  }

  if ((*primitives)->size() > 1) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("decapsulation failed: key set contains several keys (",
                     (*primitives)->size(), ") with the given ID"));
  }

  const std::unique_ptr<PrimitiveSet<KemDecapsulate>::Entry<KemDecapsulate>>&
      kem_decapsulate_entry = (**primitives).front();
  KemDecapsulate& kem_decapsulate = kem_decapsulate_entry->get_primitive();
  return kem_decapsulate.Decapsulate(ciphertext);
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<KemDecapsulate>> KemDecapsulateWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<KemDecapsulate>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) {
    return status;
  }

  return absl::make_unique<KemDecapsulateSetWrapper>(std::move(primitive_set));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
