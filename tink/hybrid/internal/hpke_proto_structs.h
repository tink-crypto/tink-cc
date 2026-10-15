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

#ifndef TINK_HYBRID_INTERNAL_HPKE_PROTO_STRUCTS_H_
#define TINK_HYBRID_INTERNAL_HPKE_PROTO_STRUCTS_H_

#include "absl/status/statusor.h"
#include "tink/hybrid/hpke_parameters.h"
#include "proto/hpke.tinkpb.h"
#include "proto/tink.tinkpb.h"

namespace crypto {
namespace tink {
namespace internal {

// Conversions between the proto representation in hpke.proto (plus the
// keyset-level output prefix type) and HpkeParameters.
absl::StatusOr<HpkeParameters> HpkeParametersFromProto(
    google::crypto::tink::internal::OutputPrefixTypeTP output_prefix_type,
    const google::crypto::tink::internal::HpkeParamsTP& params);

absl::StatusOr<google::crypto::tink::internal::HpkeParamsTP> HpkeParamsToProto(
    const HpkeParameters& parameters);

absl::StatusOr<google::crypto::tink::internal::OutputPrefixTypeTP>
HpkeVariantToOutputPrefixType(HpkeParameters::Variant variant);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_INTERNAL_HPKE_PROTO_STRUCTS_H_
