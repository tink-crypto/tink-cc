// Copyright 2022 Google LLC
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

#include "tink/keyset_handle_builder.h"

#include <cstdint>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/internal/keyset_handle_builder_entry.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::Keyset;

void SetBuilderEntryAttributes(KeyStatus status, bool is_primary,
                               absl::optional<int32_t> id,
                               KeysetHandleBuilder::Entry* entry) {
  entry->SetStatus(status);
  if (is_primary) {
    entry->SetPrimary();
  } else {
    entry->UnsetPrimary();
  }
  if (id.has_value()) {
    entry->SetFixedId(*id);
  } else {
    entry->SetRandomId();
  }
}

}  // namespace

KeysetHandleBuilder::KeysetHandleBuilder(const KeysetHandle& handle) {
  for (int i = 0; i < handle.size(); ++i) {
    KeysetHandle::Entry entry = handle[i];
    KeysetHandleBuilder::Entry builder_entry =
        KeysetHandleBuilder::Entry::CreateFromKey(
            std::move(entry.key_), entry.GetStatus(), entry.IsPrimary());
    AddEntry(std::move(builder_entry));
  }
}

KeysetHandleBuilder::Entry KeysetHandleBuilder::Entry::CreateFromKey(
    std::shared_ptr<const Key> key, KeyStatus status, bool is_primary) {
  absl::optional<int> id_requirement = key->GetIdRequirement();
  auto imported_entry = absl::make_unique<internal::KeyEntry>(std::move(key));
  KeysetHandleBuilder::Entry entry(std::move(imported_entry));
  SetBuilderEntryAttributes(status, is_primary, id_requirement, &entry);
  return entry;
}

KeysetHandleBuilder::Entry KeysetHandleBuilder::Entry::CreateFromParams(
    std::shared_ptr<const Parameters> parameters, KeyStatus status,
    bool is_primary, absl::optional<int> id) {
  auto generated_entry =
      absl::make_unique<internal::ParametersEntry>(std::move(parameters));
  KeysetHandleBuilder::Entry entry(std::move(generated_entry));
  SetBuilderEntryAttributes(status, is_primary, id, &entry);
  return entry;
}

absl::StatusOr<int32_t> KeysetHandleBuilder::NextIdFromKeyIdStrategy(
    internal::KeyIdStrategy strategy, const std::set<int32_t>& ids_so_far) {
  if (strategy.strategy == internal::KeyIdStrategyEnum::kFixedId) {
    if (!strategy.id_requirement.has_value()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Missing fixed id with fixed id strategy.");
    }
    return *strategy.id_requirement;
  }
  if (strategy.strategy == internal::KeyIdStrategyEnum::kRandomId) {
    int id = 0;
    while (id == 0 || ids_so_far.find(id) != ids_so_far.end()) {
      id = subtle::Random::GetRandomUInt32();
    }
    return id;
  }
  return absl::Status(absl::StatusCode::kInvalidArgument,
                      "Invalid key id strategy.");
}

void KeysetHandleBuilder::ClearPrimary() {
  for (KeysetHandleBuilder::Entry& entry : entries_) {
    entry.UnsetPrimary();
  }
}

KeysetHandleBuilder& KeysetHandleBuilder::AddEntry(
    KeysetHandleBuilder::Entry entry) {
  CHECK(!entry.added_to_builder_)
      << "Keyset handle builder entry already added to a builder.";
  entry.added_to_builder_ = true;
  if (entry.IsPrimary()) {
    ClearPrimary();
  }
  entries_.push_back(std::move(entry));
  return *this;
}

KeysetHandleBuilder& KeysetHandleBuilder::RemoveEntry(int index) {
  CHECK(index >= 0 && index < entries_.size())
      << "Keyset handle builder entry removal index out of range.";
  entries_.erase(entries_.begin() + index);
  return *this;
}

absl::Status KeysetHandleBuilder::CheckIdAssignments() {
  // We only want random id entries after fixed id entries. Otherwise, we might
  // randomly pick an id that is later specified as a fixed id.
  if (entries_.empty()) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "Cannot build empty keyset.");
  }
  for (int i = 0; i < entries_.size() - 1; ++i) {
    if (entries_[i].HasRandomId() && !entries_[i + 1].HasRandomId()) {
      return absl::Status(absl::StatusCode::kFailedPrecondition,
                          "Entries with random ids may only be followed "
                          "by other entries with random ids.");
    }
  }
  return absl::OkStatus();
}

KeysetHandleBuilder& KeysetHandleBuilder::SetMonitoringAnnotations(
    const absl::flat_hash_map<std::string, std::string>&
        monitoring_annotations) {
  monitoring_annotations_ = monitoring_annotations;
  return *this;
}

absl::StatusOr<KeysetHandle> KeysetHandleBuilder::Build(
    const KeyGenConfiguration& config) {
  if (build_called_) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "KeysetHandleBuilder::Build may only be called once");
  }
  build_called_ = true;
  util::SecretProto<Keyset> keyset;
  absl::optional<int> primary_id = absl::nullopt;

  absl::Status assigned_ids_status = CheckIdAssignments();
  if (!assigned_ids_status.ok()) return assigned_ids_status;

  std::set<int32_t> ids_so_far;
  for (KeysetHandleBuilder::Entry& entry : entries_) {
    absl::StatusOr<int> id =
        NextIdFromKeyIdStrategy(entry.GetKeyIdStrategy(), ids_so_far);
    if (!id.ok()) return id.status();

    if (ids_so_far.find(*id) != ids_so_far.end()) {
      return absl::Status(
          absl::StatusCode::kAlreadyExists,
          absl::StrFormat("Next id %d is already used in the keyset.", *id));
    }
    ids_so_far.insert(*id);

    absl::StatusOr<util::SecretProto<Keyset::Key>> key =
        entry.CreateKeysetKey(*id, config);
    if (!key.ok()) return key.status();

    internal::CallWithCoreDumpProtection([&]() { *keyset->add_key() = **key; });
    if (entry.IsPrimary()) {
      if (primary_id.has_value()) {
        return absl::Status(
            absl::StatusCode::kInternal,
            "Primary is already set in this keyset (should never happen since "
            "primary is cleared when a new primary is added).");
      }
      primary_id = *id;
    }
  }

  if (!primary_id.has_value()) {
    return absl::Status(absl::StatusCode::kFailedPrecondition,
                        "No primary set in this keyset.");
  }
  keyset->set_primary_key_id(*primary_id);
  absl::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandle::GetEntriesFromKeyset(*keyset);
  if (!entries.ok()) {
    return entries.status();
  }
  return KeysetHandle(std::move(keyset), *std::move(entries),
                      monitoring_annotations_);
}

}  // namespace tink
}  // namespace crypto
