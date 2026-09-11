// Copyright 2026 Google LLC
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

#include "tink/internal/primitive_set_base.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/crypto_format.h"
#include "tink/util/errors.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

PrimitiveSetBase::EntryBase::EntryBase(
    UntypedPrimitive primitive, const std::string& identifier,
    google::crypto::tink::KeyStatusType status, uint32_t key_id,
    google::crypto::tink::OutputPrefixType output_prefix_type,
    absl::string_view key_type_url)
    : primitive_(std::move(primitive)),
      identifier_(identifier),
      key_id_(key_id),
      status_(static_cast<uint8_t>(status)),
      output_prefix_type_(static_cast<uint8_t>(output_prefix_type)),
      key_type_url_(key_type_url) {}

absl::StatusOr<std::unique_ptr<PrimitiveSetBase::EntryBase>>
PrimitiveSetBase::EntryBase::New(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) {
  if (key_info.status() != google::crypto::tink::KeyStatusType::ENABLED) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "The key must be ENABLED.");
  }
  absl::StatusOr<std::string> identifier =
      key_info.output_prefix_type() ==
              google::crypto::tink::OutputPrefixType::WITH_ID_REQUIREMENT
          ? ""  // No associated prefix, so set to empty.
          : CryptoFormat::GetOutputPrefix(key_info);
  if (!identifier.ok()) {
    return identifier.status();
  }
  if (primitive == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "The primitive must be non-null.");
  }
  return absl::WrapUnique(new EntryBase(
      std::move(primitive), *identifier, key_info.status(), key_info.key_id(),
      key_info.output_prefix_type(), key_info.type_url()));
}

absl::Status PrimitiveSetBase::SetPrimaryImpl(
    EntryBase** output, EntryBase* primary,
    const CiphertextPrefixToPrimitivesMap& primitives) {
  if (!primary) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "The primary primitive must be non-null.");
  }
  if (primary->get_status() != google::crypto::tink::KeyStatusType::ENABLED) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Primary has to be enabled.");
  }

  if (primitives.count(primary->get_identifier()) == 0) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Primary cannot be set to an entry which is "
                        "not held by this primitive set.");
  }

  *output = primary;
  return absl::OkStatus();
}

absl::StatusOr<PrimitiveSetBase::EntryBase*> PrimitiveSetBase::AddPrimitiveImpl(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info,
    CiphertextPrefixToPrimitivesMap& primitives,
    std::vector<EntryBase*>& primitives_in_keyset_order) {
  absl::StatusOr<std::unique_ptr<EntryBase>> entry_or =
      EntryBase::New(std::move(primitive), key_info);
  if (!entry_or.ok()) return entry_or.status();

  std::string identifier = entry_or.value()->get_identifier();
  Primitives& primitives_for_identifier = primitives[identifier];
  primitives_for_identifier.push_back(std::move(entry_or.value()));

  EntryBase* stored_entry = primitives_for_identifier.back().get();
  primitives_in_keyset_order.push_back(stored_entry);
  return stored_entry;
}

PrimitiveSetBase::Builder& PrimitiveSetBase::Builder::AddPrimitive(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) & {
  absl::MutexLock lock(mutex_);
  if (!status_.ok()) return *this;
  status_ = AddPrimitiveImpl(std::move(primitive), key_info, primitives_,
                             primitives_in_keyset_order_)
                .status();
  return *this;
}

PrimitiveSetBase::Builder&& PrimitiveSetBase::Builder::AddPrimitive(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) && {
  return std::move(AddPrimitive(std::move(primitive), key_info));
}

PrimitiveSetBase::Builder& PrimitiveSetBase::Builder::AddPrimaryPrimitive(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) & {
  absl::MutexLock lock(mutex_);
  if (!status_.ok()) return *this;
  absl::StatusOr<EntryBase*> entry_result = AddPrimitiveImpl(
      std::move(primitive), key_info, primitives_, primitives_in_keyset_order_);
  if (!entry_result.ok()) {
    status_ = entry_result.status();
    return *this;
  }
  status_ = SetPrimaryImpl(&primary_, entry_result.value(), primitives_);
  return *this;
}

PrimitiveSetBase::Builder&& PrimitiveSetBase::Builder::AddPrimaryPrimitive(
    UntypedPrimitive primitive,
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) && {
  return std::move(AddPrimaryPrimitive(std::move(primitive), key_info));
}

PrimitiveSetBase::Builder& PrimitiveSetBase::Builder::AddAnnotations(
    absl::flat_hash_map<std::string, std::string> annotations) & {
  absl::MutexLock lock(mutex_);
  annotations_.merge(std::move(annotations));
  return *this;
}

PrimitiveSetBase::Builder&& PrimitiveSetBase::Builder::AddAnnotations(
    absl::flat_hash_map<std::string, std::string> annotations) && {
  return std::move(AddAnnotations(std::move(annotations)));
}

absl::StatusOr<PrimitiveSetBase> PrimitiveSetBase::Builder::Build() && {
  absl::MutexLock lock(mutex_);
  if (!status_.ok()) return status_;
  return PrimitiveSetBase(std::move(primitives_), primary_,
                          std::move(primitives_in_keyset_order_),
                          std::move(annotations_));
}

PrimitiveSetBase::PrimitiveSetBase(
    CiphertextPrefixToPrimitivesMap primitives, EntryBase* primary,
    std::vector<EntryBase*> primitives_in_keyset_order,
    absl::flat_hash_map<std::string, std::string> annotations)
    : primary_(primary),
      primitives_(std::move(primitives)),
      primitives_in_keyset_order_(std::move(primitives_in_keyset_order)),
      annotations_(std::move(annotations)) {}

absl::StatusOr<const PrimitiveSetBase::Primitives*>
PrimitiveSetBase::get_primitives(absl::string_view identifier) const {
  CiphertextPrefixToPrimitivesMap::const_iterator found =
      primitives_.find(identifier);
  if (found == primitives_.end()) {
    return ToStatusF(absl::StatusCode::kNotFound,
                     "No primitives found for identifier '%s'.", identifier);
  }
  return &(found->second);
}

absl::StatusOr<const PrimitiveSetBase::Primitives*>
PrimitiveSetBase::get_raw_primitives() const {
  return get_primitives(CryptoFormat::kRawPrefix);
}

const PrimitiveSetBase::EntryBase* PrimitiveSetBase::get_primary() const {
  return primary_;
}

std::vector<PrimitiveSetBase::EntryBase*> PrimitiveSetBase::get_all() const {
  std::vector<EntryBase*> result;
  for (const auto& [prefix, entry_list] : primitives_) {
    for (const std::unique_ptr<EntryBase>& entry : entry_list) {
      result.push_back(entry.get());
    }
  }
  return result;
}

std::vector<PrimitiveSetBase::EntryBase*>
PrimitiveSetBase::get_all_in_keyset_order() const {
  return primitives_in_keyset_order_;
}

std::vector<std::unique_ptr<PrimitiveSetBase::EntryBase>>
PrimitiveSetBase::ReleaseAllEntries() {
  std::vector<std::unique_ptr<EntryBase>> result;
  result.reserve(primitives_in_keyset_order_.size());
  for (EntryBase* raw_entry : primitives_in_keyset_order_) {
    std::string id = raw_entry->get_identifier();
    Primitives& list = primitives_[id];
    for (std::unique_ptr<EntryBase>& entry : list) {
      if (entry.get() == raw_entry) {
        result.push_back(std::move(entry));
        break;
      }
    }
  }
  primitives_ = CiphertextPrefixToPrimitivesMap();
  primitives_in_keyset_order_ = std::vector<EntryBase*>();
  primary_ = nullptr;
  return result;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
