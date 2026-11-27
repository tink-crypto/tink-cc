// Copyright 2017 Google Inc.
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

#include "tink/subtle/hmac_boringssl.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/mac.h"
#include "tink/mac/hmac_key.h"
#include "tink/mac/hmac_parameters.h"
#include "tink/mac/subtle/create_hmac_mac.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/secret_data.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

absl::StatusOr<HmacParameters::HashType> ToParametersHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return HmacParameters::HashType::kSha1;
    case HashType::SHA224:
      return HmacParameters::HashType::kSha224;
    case HashType::SHA256:
      return HmacParameters::HashType::kSha256;
    case HashType::SHA384:
      return HmacParameters::HashType::kSha384;
    case HashType::SHA512:
      return HmacParameters::HashType::kSha512;
    default:
      return absl::UnimplementedError(
          absl::StrCat("Unsupported hash ", EnumToString(hash_type)));
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<Mac>> HmacBoringSsl::New(HashType hash_type,
                                                        uint32_t tag_size,
                                                        SecretData key_value) {
  // CreateHmacMac already checks FIPS compatibility.
  ABSL_ASSIGN_OR_RETURN(HmacParameters::HashType params_hash_type,
                        ToParametersHashType(hash_type));
  if (tag_size > static_cast<uint32_t>(std::numeric_limits<int>::max())) {
    return absl::InvalidArgumentError("invalid tag size");
  }
  if (key_value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
    return absl::InvalidArgumentError("invalid key size");
  }
  ABSL_ASSIGN_OR_RETURN(
      HmacParameters parameters,
      HmacParameters::Create(static_cast<int>(key_value.size()),
                             static_cast<int>(tag_size), params_hash_type,
                             HmacParameters::Variant::kNoPrefix));
  ABSL_ASSIGN_OR_RETURN(
      HmacKey key,
      HmacKey::Create(
          parameters,
          RestrictedData(std::move(key_value), InsecureSecretKeyAccess::Get()),
          /*id_requirement=*/std::nullopt, GetPartialKeyAccess()));
  return CreateHmacMac(key);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
