// Copyright 2021 Google LLC
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

#ifndef TINK_JWT_INTERNAL_JWT_MAC_WRAPPER_H_
#define TINK_JWT_INTERNAL_JWT_MAC_WRAPPER_H_

#include <memory>

#include "absl/status/statusor.h"
#include "tink/jwt/internal/jwt_mac_internal.h"
#include "tink/jwt/jwt_mac.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"

namespace crypto {
namespace tink {
namespace jwt_internal {

// Wraps a set of JwtMac-instances that correspond to a keyset,
// and combines them into a single JwtMac-primitive, that uses the provided
// instances, depending on the context:
//   * JwtMac::ComputeMacAndEncode(...) uses the primary instance from the set
//   * JwtMac::VerifyMacAndDecode(...) uses all instance from the set
// only keys with RAW output prefix are supported.
class JwtMacWrapper : public PrimitiveWrapper<JwtMacInternal, JwtMac> {
 public:
  absl::StatusOr<std::unique_ptr<JwtMac>> Wrap(
      std::unique_ptr<PrimitiveSet<JwtMacInternal>> jwt_mac_set) const override;
};

}  // namespace jwt_internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_INTERNAL_JWT_MAC_WRAPPER_H_
