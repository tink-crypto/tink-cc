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

#ifndef TINK_INTERNAL_PRIMITIVE_SET_BASE_H_
#define TINK_INTERNAL_PRIMITIVE_SET_BASE_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Type-erased base container class for a set of primitives.
class PrimitiveSetBase {
 public:
  // Storing a type-erased `void*` in `std::unique_ptr` requires a custom
  // deleter function pointer because `delete static_cast<void*>(ptr)` is
  // undefined behavior in C++. The deleter function pointer `void (*)(void*)`
  // captures the type-specific destructor at creation time to safely delete
  // the type-erased object when the `unique_ptr` is destroyed.
  using UntypedPrimitive = std::unique_ptr<void, void (*)(void*)>;

  // EntryBase holds individual instances of type-erased primitives in the set.
  class EntryBase {
   public:
    static absl::StatusOr<std::unique_ptr<EntryBase>> New(
        UntypedPrimitive primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info);

    virtual ~EntryBase() = default;

    void* get_untyped_primitive() const { return primitive_.get(); }
    void* ReleaseUntypedPrimitive() { return primitive_.release(); }

    // Returns an empty string if the output prefix type is WITH_ID_REQUIREMENT.
    // Otherwise, it returns the corresponding output prefix according to
    // `CryptoFormat::GetOutputPrefix()`.
    const std::string& get_identifier() const { return identifier_; }

    google::crypto::tink::KeyStatusType get_status() const {
      return static_cast<google::crypto::tink::KeyStatusType>(status_);
    }

    uint32_t get_key_id() const { return key_id_; }

    google::crypto::tink::OutputPrefixType get_output_prefix_type() const {
      return static_cast<google::crypto::tink::OutputPrefixType>(
          output_prefix_type_);
    }

    absl::string_view get_key_type_url() const { return key_type_url_; }

   protected:
    EntryBase(UntypedPrimitive primitive, const std::string& identifier,
              google::crypto::tink::KeyStatusType status, uint32_t key_id,
              google::crypto::tink::OutputPrefixType output_prefix_type,
              absl::string_view key_type_url);

   private:
    UntypedPrimitive primitive_;
    std::string identifier_;
    uint32_t key_id_;
    uint8_t status_;
    uint8_t output_prefix_type_;
    const std::string key_type_url_;
  };

  using Primitives = std::vector<std::unique_ptr<EntryBase>>;
  using CiphertextPrefixToPrimitivesMap =
      absl::flat_hash_map<std::string, Primitives>;

  // Builder is used to construct PrimitiveSet objects. Objects returned by
  // the builder are immutable. Calling any of the non-const methods on them
  // will fail.
  class Builder {
   public:
    // Adds 'primitive' to this set for the specified 'key'.
    Builder& AddPrimitive(
        UntypedPrimitive primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) &;
    Builder&& AddPrimitive(
        UntypedPrimitive primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) &&;

    // Adds 'primitive' to this set for the specified 'key' and marks it
    // primary.
    Builder& AddPrimaryPrimitive(
        UntypedPrimitive primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) &;
    Builder&& AddPrimaryPrimitive(
        UntypedPrimitive primitive,
        const google::crypto::tink::KeysetInfo::KeyInfo& key_info) &&;

    // Add the given annotations. Existing annotations will not be overwritten.
    Builder& AddAnnotations(
        absl::flat_hash_map<std::string, std::string> annotations) &;
    Builder&& AddAnnotations(
        absl::flat_hash_map<std::string, std::string> annotations) &&;

    absl::StatusOr<PrimitiveSetBase> Build() &&;

   private:
    EntryBase* primary_ ABSL_GUARDED_BY(mutex_) = nullptr;
    CiphertextPrefixToPrimitivesMap primitives_ ABSL_GUARDED_BY(mutex_);
    std::vector<EntryBase*> primitives_in_keyset_order_ ABSL_GUARDED_BY(mutex_);
    absl::flat_hash_map<std::string, std::string> annotations_
        ABSL_GUARDED_BY(mutex_);
    absl::Mutex mutex_;
    absl::Status status_ ABSL_GUARDED_BY(mutex_);
  };

  // PrimitiveSetBase is movable, but not copyable
  PrimitiveSetBase(PrimitiveSetBase&&) = default;
  PrimitiveSetBase& operator=(PrimitiveSetBase&&) = default;
  PrimitiveSetBase(const PrimitiveSetBase&) = delete;
  PrimitiveSetBase& operator=(const PrimitiveSetBase&) = delete;

  // Constructs an empty PrimitiveSetBase.
  PrimitiveSetBase() = default;

  // Returns the entries with primitives identified by 'identifier'.
  absl::StatusOr<const Primitives*> get_primitives(
      absl::string_view identifier) const;

  // Returns all primitives that use RAW prefix.
  absl::StatusOr<const Primitives*> get_raw_primitives() const;

  // Returns the entry with the primary primitive.
  const EntryBase* get_primary() const;

  // Returns all entries.
  std::vector<EntryBase*> get_all() const;

  // Returns all entries in the original keyset key order.
  std::vector<EntryBase*> get_all_in_keyset_order() const;

  std::vector<std::unique_ptr<EntryBase>> ReleaseAllEntries();
  const absl::flat_hash_map<std::string, std::string>& get_annotations() const {
    return annotations_;
  }

 private:
  friend class Builder;
  friend class PrimitiveSetBaseInternalTest;

  // Constructs an empty PrimitiveSetBase.
  // Note: This is equivalent to PrimitiveSetBase(/*annotations=*/{}).
  PrimitiveSetBase(CiphertextPrefixToPrimitivesMap primitives,
                   EntryBase* primary,
                   std::vector<EntryBase*> primitives_in_keyset_order,
                   absl::flat_hash_map<std::string, std::string> annotations);

  // Helper methods for mutations, used by the Builder.
  static absl::Status SetPrimaryImpl(
      EntryBase** output, EntryBase* primary,
      const CiphertextPrefixToPrimitivesMap& primitives);

  static absl::StatusOr<EntryBase*> AddPrimitiveImpl(
      UntypedPrimitive primitive,
      const google::crypto::tink::KeysetInfo::KeyInfo& key_info,
      CiphertextPrefixToPrimitivesMap& primitives,
      std::vector<EntryBase*>& primitives_in_keyset_order);

  // Owned by primitives_.
  EntryBase* primary_ = nullptr;
  CiphertextPrefixToPrimitivesMap primitives_;
  // Entries in the original keyset key order, all owned by primitives_.
  std::vector<EntryBase*> primitives_in_keyset_order_;
  absl::flat_hash_map<std::string, std::string> annotations_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PRIMITIVE_SET_BASE_H_
