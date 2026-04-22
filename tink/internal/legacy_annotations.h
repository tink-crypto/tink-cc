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

#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "tink/annotations.h"

#ifndef TINK_INTERNAL_LEGACY_ANNOTATIONS_H_
#define TINK_INTERNAL_LEGACY_ANNOTATIONS_H_

namespace crypto {
namespace tink {
namespace internal {

class LegacyAnnotations : public ::crypto::tink::Annotations {
 public:
  explicit LegacyAnnotations(
      absl::flat_hash_map<std::string, std::string> annotations)
      : annotations_(std::move(annotations)) {}

  LegacyAnnotations(const LegacyAnnotations& other) = default;
  LegacyAnnotations& operator=(const LegacyAnnotations& other) = default;
  LegacyAnnotations(LegacyAnnotations&& other) = default;
  LegacyAnnotations& operator=(LegacyAnnotations&& other) = default;

  const absl::flat_hash_map<std::string, std::string>& GetMap() const {
    return annotations_;
  }

  Annotations* Clone() const override {
    return new LegacyAnnotations(*this);
  }

 private:
  absl::flat_hash_map<std::string, std::string> annotations_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_LEGACY_ANNOTATIONS_H_
