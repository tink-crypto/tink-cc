// Copyright 2019 Google LLC
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

#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"

#include <memory>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/streamingaead/internal/aes_ctr_hmac_streaming.h"
#include "tink/subtle/random.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/validation.h"
#include "proto/common.pb.h"

namespace crypto {
namespace tink {

using ::google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using ::google::crypto::tink::AesCtrHmacStreamingParams;
using ::google::crypto::tink::HashType;

namespace {

constexpr int kNoncePrefixSizeInBytes = 7;

absl::StatusOr<AesCtrHmacStreamingParameters::HashType> FromProtoHashType(
    HashType hash_type) {
  switch (hash_type) {
    case HashType::SHA1:
      return AesCtrHmacStreamingParameters::HashType::kSha1;
    case HashType::SHA256:
      return AesCtrHmacStreamingParameters::HashType::kSha256;
    case HashType::SHA512:
      return AesCtrHmacStreamingParameters::HashType::kSha512;
    default:
      return absl::InvalidArgumentError("Unsupported proto hash type");
  }
}

absl::Status ValidateParams(const AesCtrHmacStreamingParams& params) {
  if (!(params.hkdf_hash_type() == HashType::SHA1 ||
        params.hkdf_hash_type() == HashType::SHA256 ||
        params.hkdf_hash_type() == HashType::SHA512)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported hkdf_hash_type");
  }
  if (!(params.hmac_params().hash() == HashType::SHA1 ||
        params.hmac_params().hash() == HashType::SHA256 ||
        params.hmac_params().hash() == HashType::SHA512)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported hmac_params.hash");
  }
  if (params.hmac_params().tag_size() < 10) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "hmac_params.tag_size too small");
  }
  if ((params.hmac_params().hash() == HashType::SHA1 &&
       params.hmac_params().tag_size() > 20) ||
      (params.hmac_params().hash() == HashType::SHA256 &&
       params.hmac_params().tag_size() > 32) ||
      (params.hmac_params().hash() == HashType::SHA512 &&
       params.hmac_params().tag_size() > 64)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "hmac_params.tag_size too big");
  }
  int header_size = 1 + params.derived_key_size() + kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size() <=
      header_size + params.hmac_params().tag_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too small");
  }
  if (params.ciphertext_segment_size() > 0x7fffffff) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too big");
  }
  return ValidateAesKeySize(params.derived_key_size());
}

}  // namespace

absl::StatusOr<std::unique_ptr<StreamingAead>>
AesCtrHmacStreamingKeyManager::StreamingAeadFactory::Create(
    const google::crypto::tink::AesCtrHmacStreamingKey& key) const {
  ABSL_ASSIGN_OR_RETURN(AesCtrHmacStreamingParameters::HashType hkdf_hash_type,
                        FromProtoHashType(key.params().hkdf_hash_type()));
  ABSL_ASSIGN_OR_RETURN(AesCtrHmacStreamingParameters::HashType hmac_hash_type,
                        FromProtoHashType(key.params().hmac_params().hash()));
  ABSL_ASSIGN_OR_RETURN(
      AesCtrHmacStreamingParameters parameters,
      AesCtrHmacStreamingParameters::Builder()
          .SetKeySizeInBytes(key.key_value().size())
          .SetDerivedKeySizeInBytes(key.params().derived_key_size())
          .SetHkdfHashType(hkdf_hash_type)
          .SetHmacHashType(hmac_hash_type)
          .SetHmacTagSizeInBytes(key.params().hmac_params().tag_size())
          .SetCiphertextSegmentSizeInBytes(
              key.params().ciphertext_segment_size())
          .Build());
  ABSL_ASSIGN_OR_RETURN(
      crypto::tink::AesCtrHmacStreamingKey streaming_key,
      crypto::tink::AesCtrHmacStreamingKey::Create(
          parameters,
          RestrictedData(key.key_value(), InsecureSecretKeyAccess::Get()),
          GetPartialKeyAccess()));
  return internal::NewAesCtrHmacStreaming(streaming_key);
}

absl::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
AesCtrHmacStreamingKeyManager::CreateKey(
    const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format)
    const {
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
  *key.mutable_params() = key_format.params();
  return key;
};

absl::StatusOr<google::crypto::tink::AesCtrHmacStreamingKey>
AesCtrHmacStreamingKeyManager::DeriveKey(
    const google::crypto::tink::AesCtrHmacStreamingKeyFormat& key_format,
    InputStream* input_stream) const {
  absl::Status status = ValidateVersion(key_format.version(), get_version());
  if (!status.ok()) return status;

  absl::StatusOr<SecretData> randomness_or =
      ReadSecretBytesFromStream(key_format.key_size(), input_stream);
  if (!randomness_or.ok()) {
    return randomness_or.status();
  }
  google::crypto::tink::AesCtrHmacStreamingKey key;
  key.set_version(get_version());
  key.set_key_value(util::SecretDataAsStringView(*randomness_or));
  *key.mutable_params() = key_format.params();
  return key;
}

absl::Status AesCtrHmacStreamingKeyManager::ValidateKey(
    const google::crypto::tink::AesCtrHmacStreamingKey& key) const {
  absl::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (key.key_value().size() < key.params().derived_key_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_value (i.e. ikm) too short");
  }
  return ValidateParams(key.params());
}

absl::Status AesCtrHmacStreamingKeyManager::ValidateKeyFormat(
    const AesCtrHmacStreamingKeyFormat& key_format) const {
  if (key_format.key_size() < key_format.params().derived_key_size()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "key_size must not be smaller than derived_key_size");
  }
  return ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
