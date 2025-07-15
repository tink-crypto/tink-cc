// Copyright 2025 Google LLC
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
#ifndef TINK_INTERNAL_MONITORING_KEY_SET_INFO_H_
#define TINK_INTERNAL_MONITORING_KEY_SET_INFO_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "tink/internal/key_status_util.h"
#include "tink/key_status.h"

namespace crypto::tink::internal {

// Immutable representation of a KeySet in a certain point in time for the
// purpose of monitoring operations involving cryptographic keys.
class MonitoringKeySetInfo {
 public:
  // Description about each entry of the KeySet.
  class Entry {
   public:
    // Constructs a new KeySet entry with a given `status`, `key_id`,
    // `key_type`, and `key_prefix`.
    Entry(KeyStatus status, uint32_t key_id, absl::string_view key_type,
          absl::string_view key_prefix)
        : status_(status),
          key_id_(key_id),
          key_type_(key_type),
          key_prefix_(key_prefix) {}
    Entry(const Entry& other) = default;
    Entry& operator=(const Entry& other) = default;
    Entry(Entry&& other) = default;
    Entry& operator=(Entry&& other) = default;

    // Returns the status of this entry.
    std::string GetStatus() const { return internal::ToKeyStatusName(status_); }
    // Returns the ID of the entry within the keyset.
    uint32_t GetKeyId() const { return key_id_; }
    // Returns the key type.
    std::string GetKeyType() const { return key_type_; }
    // Returns the key prefix.
    std::string GetKeyPrefix() const { return key_prefix_; }

   private:
    // Status of this entry.
    KeyStatus status_;
    // Identifies a key within a keyset.
    uint32_t key_id_;
    // This field stores the key type.
    std::string key_type_;
    // Stores the key output prefix.
    std::string key_prefix_;
  };

  // Constructs a MonitoringKeySetInfo object with the given
  // `keyset_annotations`, `keyset_entries` and primary key ID `primary_key_id`.
  MonitoringKeySetInfo(
      const absl::flat_hash_map<std::string, std::string>& keyset_annotations,
      const std::vector<Entry>& keyset_entries, uint32_t primary_key_id)
      : keyset_annotations_(keyset_annotations),
        keyset_entries_(keyset_entries),
        primary_key_id_(primary_key_id) {}

  MonitoringKeySetInfo(MonitoringKeySetInfo&& other) = default;
  MonitoringKeySetInfo& operator=(MonitoringKeySetInfo&& other) = default;
  MonitoringKeySetInfo(const MonitoringKeySetInfo& other) = default;
  MonitoringKeySetInfo& operator=(const MonitoringKeySetInfo& other) = default;

  // Returns a const reference to the annotations of this keyset.
  const absl::flat_hash_map<std::string, std::string>& GetAnnotations() const {
    return keyset_annotations_;
  }
  // Returns a const reference to the array of entries for this keyset.
  const std::vector<Entry>& GetEntries() const { return keyset_entries_; }
  // Returns the ID of the primary key in this keyset.
  uint32_t GetPrimaryKeyId() const { return primary_key_id_; }

 private:
  // Annotations of this keyset in the form 'key' -> 'value'.
  absl::flat_hash_map<std::string, std::string> keyset_annotations_;
  std::vector<Entry> keyset_entries_;
  uint32_t primary_key_id_;
};

}  // namespace crypto::tink::internal

#endif  // TINK_INTERNAL_MONITORING_KEY_SET_INFO_H_
