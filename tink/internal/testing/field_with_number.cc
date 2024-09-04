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

#include "tink/internal/testing/field_with_number.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parsing_helpers.h"
#include "tink/restricted_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace proto_testing {

using ::crypto::tink::internal::proto_parsing::SerializeVarint;
using ::crypto::tink::internal::proto_parsing::WireType;

namespace {

std::string WiretypeAndFieldNumber(WireType wire_type, int field_number) {
  std::string result;
  result.resize(
      proto_parsing::WireTypeAndFieldNumberLength(wire_type, field_number));
  absl::Span<char> result_span = absl::MakeSpan(result);
  CHECK_OK(proto_parsing::SerializeWireTypeAndFieldNumber(
      wire_type, field_number, result_span));
  return result;
}

std::string SerializeVarintToString(uint64_t v) {
  std::string result;
  result.resize(crypto::tink::internal::proto_parsing::VarintLength(v));
  absl::Span<char> result_span = absl::MakeSpan(result);
  CHECK_OK(SerializeVarint(v, result_span));
  return result;
}

}  // namespace

std::string FieldWithNumber::IsVarint(uint64_t v) {
  return absl::StrCat(WiretypeAndFieldNumber(WireType::kVarint, field_number_),
                      SerializeVarintToString(v));
}

std::string FieldWithNumber::IsString(absl::string_view v) {
  return absl::StrCat(
      WiretypeAndFieldNumber(WireType::kLengthDelimited, field_number_),
      SerializeVarintToString(v.size()), v);
}
std::string FieldWithNumber::IsSubMessage(const std::vector<std::string>& s) {
  return IsString(absl::StrJoin(s, ""));
}

ProtoKeySerialization SerializeMessage(
    absl::string_view type_url, const std::vector<std::string>& v,
    google::crypto::tink::KeyData::KeyMaterialType key_material_type,
    google::crypto::tink::OutputPrefixType output_prefix_type,
    absl::optional<int> id_requirement) {
  absl::StatusOr<ProtoKeySerialization> result = ProtoKeySerialization::Create(
      type_url,
      RestrictedData(absl::StrJoin(v, ""), InsecureSecretKeyAccess::Get()),
      key_material_type, output_prefix_type, id_requirement);
  CHECK_OK(result.status());
  return *result;
}

}  // namespace proto_testing
}  // namespace internal
}  // namespace tink
}  // namespace crypto
