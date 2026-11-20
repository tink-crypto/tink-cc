// Copyright 2026 Google LLC
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

#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/fips_utils.h"
#include "tink/partial_key_access.h"
#include "tink/secret_data.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_decrypter.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/nonce_based_streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::HashType> ToSubtleHashType(
    AesGcmHkdfStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesGcmHkdfStreamingParameters::HashType::kSha1:
      return subtle::HashType::SHA1;
    case AesGcmHkdfStreamingParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case AesGcmHkdfStreamingParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported hash type");
  }
}

class AesGcmHkdfStreamingImpl final : public subtle::NonceBasedStreamingAead {
 public:
  AesGcmHkdfStreamingImpl(SecretData ikm, subtle::HashType hkdf_hash,
                          int derived_key_size, int ciphertext_segment_size)
      : ikm_(std::move(ikm)),
        hkdf_hash_(hkdf_hash),
        derived_key_size_(derived_key_size),
        ciphertext_segment_size_(ciphertext_segment_size) {}

 protected:
  absl::StatusOr<std::unique_ptr<subtle::StreamSegmentEncrypter>>
  NewSegmentEncrypter(absl::string_view associated_data) const override {
    subtle::AesGcmHkdfStreamSegmentEncrypter::Params params;
    params.salt = subtle::Random::GetRandomBytes(derived_key_size_);
    ABSL_ASSIGN_OR_RETURN(params.key, subtle::Hkdf::ComputeHkdf(
                                          hkdf_hash_, ikm_, params.salt,
                                          associated_data, derived_key_size_));
    params.ciphertext_offset = 0;
    params.ciphertext_segment_size = ciphertext_segment_size_;
    return subtle::AesGcmHkdfStreamSegmentEncrypter::New(std::move(params));
  }

  absl::StatusOr<std::unique_ptr<subtle::StreamSegmentDecrypter>>
  NewSegmentDecrypter(absl::string_view associated_data) const override {
    subtle::AesGcmHkdfStreamSegmentDecrypter::Params params;
    params.ikm = ikm_;
    params.hkdf_hash = hkdf_hash_;
    params.derived_key_size = derived_key_size_;
    params.ciphertext_offset = 0;
    params.ciphertext_segment_size = ciphertext_segment_size_;
    params.associated_data = std::string(associated_data);
    return subtle::AesGcmHkdfStreamSegmentDecrypter::New(std::move(params));
  }

 private:
  const SecretData ikm_;
  const subtle::HashType hkdf_hash_;
  const int derived_key_size_;
  const int ciphertext_segment_size_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<StreamingAead>> NewAesGcmHkdfStreaming(
    const AesGcmHkdfStreamingKey& key) {
  ABSL_RETURN_IF_ERROR(ChecksFipsCompatibility(FipsCompatibility::kNotFips));
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hkdf_hash,
                        ToSubtleHashType(key.GetParameters().GetHashType()));
  SecretData ikm = key.GetInitialKeyMaterial(GetPartialKeyAccess())
                       .Get(InsecureSecretKeyAccess::Get());
  return std::make_unique<AesGcmHkdfStreamingImpl>(
      std::move(ikm), hkdf_hash, key.GetParameters().DerivedKeySizeInBytes(),
      key.GetParameters().CiphertextSegmentSizeInBytes());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
