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

#ifndef TINK_PROTO_PARAMETERS_FORMAT_H_
#define TINK_PROTO_PARAMETERS_FORMAT_H_

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/parameters.h"

namespace crypto {
namespace tink {

// Serialize `parameters` into Tink's binary format based on protobufs.
absl::StatusOr<std::string> SerializeParametersToProtoFormat(
    const Parameters& parameters);

// Parse `serialized_parameters` from Tink's binary format based on protobufs.
absl::StatusOr<std::unique_ptr<Parameters>> ParseParametersFromProtoFormat(
    absl::string_view serialized_parameters);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PROTO_PARAMETERS_FORMAT_H_
