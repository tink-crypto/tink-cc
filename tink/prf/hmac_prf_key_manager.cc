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
#include "tink/prf/hmac_prf_key_manager.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>

#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/input_stream.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/hmac_prf.pb.h"

namespace crypto {
namespace tink {
namespace {
constexpr int kMinKeySizeInBytes = 16;
}

using HmacPrfKeyProto = ::google::crypto::tink::HmacPrfKey;
using ::crypto::tink::subtle::HashType;
using ::crypto::tink::util::Enums;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HmacPrfKeyFormat;
using ::google::crypto::tink::HmacPrfParams;

util::Status HmacPrfKeyManager::ValidateKey(const HmacPrfKeyProto& key) const {
  util::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacPrfKey: key_value wrong length.");
  }
  return ValidateParams(key.params());
}

util::Status HmacPrfKeyManager::ValidateKeyFormat(
    const HmacPrfKeyFormat& key_format) const {
  util::Status status = ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;
  if (key_format.key_size() < kMinKeySizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid HmacPrfKeyFormat: invalid key_size.");
  }
  return ValidateParams(key_format.params());
}

crypto::tink::util::StatusOr<HmacPrfKeyProto> HmacPrfKeyManager::CreateKey(
    const HmacPrfKeyFormat& key_format) const {
  HmacPrfKeyProto key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  *(key.mutable_params()) = key_format.params();
  return key;
}

StatusOr<HmacPrfKeyProto> HmacPrfKeyManager::DeriveKey(
    const HmacPrfKeyFormat& hmac_prf_key_format,
    InputStream* input_stream) const {
  crypto::tink::util::Status status = ValidateKeyFormat(hmac_prf_key_format);
  if (!status.ok()) return status;

  crypto::tink::util::StatusOr<std::string> randomness =
      ReadBytesFromStream(hmac_prf_key_format.key_size(), input_stream);
  if (!randomness.status().ok()) {
    return randomness.status();
  }

  HmacPrfKeyProto key;
  key.set_version(get_version());
  *(key.mutable_params()) = hmac_prf_key_format.params();
  key.set_key_value(randomness.value());
  return key;
}

Status HmacPrfKeyManager::ValidateParams(const HmacPrfParams& params) const {
  static const std::set<HashType>* supported_hash_types =
      new std::set<HashType>({HashType::SHA1, HashType::SHA224,
                              HashType::SHA256, HashType::SHA384,
                              HashType::SHA512});
  if (supported_hash_types->find(Enums::ProtoToSubtle(params.hash())) ==
      supported_hash_types->end()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Invalid HmacParams: HashType '%s' not supported.",
                     Enums::HashName(params.hash()));
  }
  return util::OkStatus();
}

absl::optional<uint64_t> HmacPrfKeyManager::MaxOutputLength(
    subtle::HashType hash_type) {
  static std::map<subtle::HashType, uint64_t>* max_output_length =
      new std::map<subtle::HashType, uint64_t>(
          {{subtle::HashType::SHA1, 20},
           {subtle::HashType::SHA224, 28},
           {subtle::HashType::SHA256, 32},
           {subtle::HashType::SHA384, 48},
           {subtle::HashType::SHA512, 64}});
  auto length_it = max_output_length->find(hash_type);
  if (length_it == max_output_length->end()) {
    return absl::nullopt;
  }
  return length_it->second;
}

}  // namespace tink
}  // namespace crypto
