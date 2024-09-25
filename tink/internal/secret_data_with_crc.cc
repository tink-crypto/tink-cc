// Copyright 2024 Google LLC
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

#include "tink/internal/secret_data_with_crc.h"

#include <string_view>
#include <utility>

#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/internal/call_with_core_dump_protection.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::internal::CallWithCoreDumpProtection;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataAsStringView;
using ::crypto::tink::util::SecretDataFromStringView;
using ::crypto::tink::util::SecretValue;

bool IsValidSecretcCrc32c(absl::string_view data,
                          const SecretValue<absl::crc32c_t>& expected_crc) {
  return CallWithCoreDumpProtection(
      [&]() { return absl::ComputeCrc32c(data) == expected_crc.value(); });
}

SecretValue<absl::crc32c_t> ComputeSecretCrc32c(absl::string_view data) {
  return CallWithCoreDumpProtection(
      [&]() { return SecretValue<absl::crc32c_t>(absl::ComputeCrc32c(data)); });
}

}  // namespace

SecretDataWithCrc::SecretDataWithCrc(
    SecretData data, absl::optional<SecretValue<absl::crc32c_t>> crc)
    : data_(std::move(data)),
      crc_(crc.has_value()
               ? crc.value()
               : ComputeSecretCrc32c(SecretDataAsStringView(data_))) {}

SecretDataWithCrc::SecretDataWithCrc(
    absl::string_view data, absl::optional<SecretValue<absl::crc32c_t>> crc)
    : SecretDataWithCrc(SecretDataFromStringView(data), std::move(crc)) {}

absl::string_view SecretDataWithCrc::UncheckedData() const {
  return SecretDataAsStringView(data_);
}

absl::StatusOr<absl::string_view> SecretDataWithCrc::data() const {
  if (!IsValidSecretcCrc32c(SecretDataAsStringView(data_), crc_)) {
    return absl::DataLossError("data CRC verification failed");
  }
  return SecretDataAsStringView(data_);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
