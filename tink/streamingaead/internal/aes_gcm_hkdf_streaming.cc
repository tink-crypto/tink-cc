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
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/subtle/aes_gcm_hkdf_streaming.h"
#include "tink/subtle/common_enums.h"

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

}  // namespace

absl::StatusOr<std::unique_ptr<StreamingAead>> NewAesGcmHkdfStreaming(
    const AesGcmHkdfStreamingKey& key) {
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hkdf_hash,
                        ToSubtleHashType(key.GetParameters().GetHashType()));
  subtle::AesGcmHkdfStreaming::Params params;
  params.ikm = key.GetInitialKeyMaterial(GetPartialKeyAccess())
                   .Get(InsecureSecretKeyAccess::Get());
  params.hkdf_hash = hkdf_hash;
  params.derived_key_size = key.GetParameters().DerivedKeySizeInBytes();
  params.ciphertext_segment_size =
      key.GetParameters().CiphertextSegmentSizeInBytes();
  params.ciphertext_offset = 0;
  return subtle::AesGcmHkdfStreaming::New(std::move(params));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
