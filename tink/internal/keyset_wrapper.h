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
///////////////////////////////////////////////////////////////////////////////
#ifndef TINK_INTERNAL_KEYSET_WRAPPER_H_
#define TINK_INTERNAL_KEYSET_WRAPPER_H_

#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Keyset wrappers wrap a Tink Keyset into a set of primitives. These are
// internal Tink objects created from a PrimitiveWrapper<P, Q>.
//
// In `PrimitiveWrapper<P, Q>`, `P` is the intermediate primitive created from
// each individual key, and `Q` is the wrapped primitive returned to the caller.
//
// `KeysetWrapperImpl<P, Q>` implements `KeysetWrapper<Q>`, performing type
// erasure on `P` when the wrapper is registered.
//
// `UntypedKeysetWrapperImpl<Primitive>` implements `UntypedKeysetWrapper`,
// further type-erasing `Primitive` into `void*` so that keyset primitive
// resolution and wrapping can be performed without template instantiation at
// call sites.

// A non-templated base interface for keyset wrappers that allows type-erased
// execution of primitive wrapping without knowing the primitive type at compile
// time.
class UntypedKeysetWrapper {
 public:
  virtual ~UntypedKeysetWrapper() = default;

  // Wraps a given `keyset` with annotations `annotations`, returning an untyped
  // pointer to the wrapped primitive. Caller takes ownership of the pointer.
  virtual absl::StatusOr<void*> WrapVoid(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations)
      const = 0;
};

// Strongly-typed interface for wrapping a Keyset into a specific primitive.
template <typename Primitive>
class KeysetWrapper {
 public:
  virtual ~KeysetWrapper() = default;

  // Wraps a given `keyset` with annotations `annotations`.
  virtual absl::StatusOr<std::unique_ptr<Primitive>> Wrap(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations)
      const = 0;
};

// Adapter that wraps a typed `KeysetWrapper<Primitive>` into an
// `UntypedKeysetWrapper` to enable type-erased primitive creation.
template <typename Primitive>
class UntypedKeysetWrapperImpl : public UntypedKeysetWrapper {
 public:
  explicit UntypedKeysetWrapperImpl(
      std::unique_ptr<KeysetWrapper<Primitive>> keyset_wrapper)
      : keyset_wrapper_(std::move(keyset_wrapper)) {}

  // Wraps `keyset` into a primitive of type `Primitive` using the underlying
  // typed wrapper and returns the allocated primitive as an untyped `void*`.
  // The caller takes ownership of the returned pointer.
  absl::StatusOr<void*> WrapVoid(
      const google::crypto::tink::Keyset& keyset,
      const absl::flat_hash_map<std::string, std::string>& annotations)
      const override {
    absl::StatusOr<std::unique_ptr<Primitive>> primitive =
        keyset_wrapper_->Wrap(keyset, annotations);
    if (!primitive.ok()) {
      return primitive.status();
    }
    return static_cast<void*>(primitive->release());
  }

  // Returns a pointer to the underlying typed `KeysetWrapper<Primitive>`.
  const KeysetWrapper<Primitive>* GetTypedWrapper() const {
    return keyset_wrapper_.get();
  }

 private:
  std::unique_ptr<KeysetWrapper<Primitive>> keyset_wrapper_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEYSET_WRAPPER_H_
