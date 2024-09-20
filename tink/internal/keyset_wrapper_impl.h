// Copyright 2020 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_KEYSET_WRAPPER_IMPL_H_
#define TINK_INTERNAL_KEYSET_WRAPPER_IMPL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_info.h"
#include "tink/internal/keyset_wrapper.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/key.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

template <typename P, typename Q>
class KeysetWrapperImpl : public KeysetWrapper<Q> {
 public:
  explicit KeysetWrapperImpl(
      const PrimitiveWrapper<P, Q>* transforming_wrapper,
      absl::AnyInvocable<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
          const google::crypto::tink::KeyData& key_data) const>
          primitive_getter,
      absl::AnyInvocable<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
          const Key& key) const>
          primitive_getter_from_key)
      : primitive_getter_(std::move(primitive_getter)),
        primitive_getter_from_key_(std::move(primitive_getter_from_key)),

        transforming_wrapper_(*transforming_wrapper) {}

  crypto::tink::util::StatusOr<std::unique_ptr<Q>> Wrap(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations)
      const override {
    crypto::tink::util::Status status = ValidateKeyset(keyset);
    if (!status.ok()) return status;
    typename PrimitiveSet<P>::Builder primitives_builder;
    primitives_builder.AddAnnotations(annotations);
    for (const google::crypto::tink::Keyset::Key& proto_key : keyset.key()) {
      if (proto_key.status() != google::crypto::tink::KeyStatusType::ENABLED) {
        continue;
      }

      // Get the proto key serialization.
      util::StatusOr<internal::ProtoKeySerialization> serialization =
          internal::ProtoKeySerialization::Create(
              proto_key.key_data().type_url(),
              RestrictedData(proto_key.key_data().value(),
                             InsecureSecretKeyAccess::Get()),
              proto_key.key_data().key_material_type(),
              google::crypto::tink::OutputPrefixType::RAW,
              /*id_requirement=*/absl::nullopt);
      if (!serialization.ok()) {
        return serialization.status();
      }

      util::StatusOr<std::unique_ptr<const Key>> key =
          internal::MutableSerializationRegistry::GlobalInstance().ParseKey(
              *serialization, InsecureSecretKeyAccess::Get());

      util::StatusOr<std::unique_ptr<P>> primitive;
      if (!key.ok() ||
          primitive_getter_from_key_(*key.value()).status().code() ==
              absl::StatusCode::kNotFound) {
        // Try the legacy way.
        primitive = primitive_getter_(proto_key.key_data());
      } else {
        primitive = primitive_getter_from_key_(*key.value());
      }

      if (!primitive.ok()) {
        return primitive.status();
      }

      if (proto_key.key_id() == keyset.primary_key_id()) {
        primitives_builder.AddPrimaryPrimitive(std::move(primitive.value()),
                                               KeyInfoFromKey(proto_key));
      } else {
        primitives_builder.AddPrimitive(std::move(primitive.value()),
                                        KeyInfoFromKey(proto_key));
      }
    }
    crypto::tink::util::StatusOr<PrimitiveSet<P>> primitives =
        std::move(primitives_builder).Build();
    if (!primitives.ok()) return primitives.status();
    return transforming_wrapper_.Wrap(
        absl::make_unique<PrimitiveSet<P>>(*std::move(primitives)));
  }

 private:
  absl::AnyInvocable<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
      const google::crypto::tink::KeyData& key_data) const>
      primitive_getter_;
  absl::AnyInvocable<crypto::tink::util::StatusOr<std::unique_ptr<P>>(
      const Key& key) const>
      primitive_getter_from_key_;
  const PrimitiveWrapper<P, Q>& transforming_wrapper_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEYSET_WRAPPER_IMPL_H_
