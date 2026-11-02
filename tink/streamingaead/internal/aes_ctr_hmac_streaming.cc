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

#include "tink/streamingaead/internal/aes_ctr_hmac_streaming.h"

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"
#include "tink/subtle/aes_ctr_hmac_streaming.h"
#include "tink/subtle/common_enums.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

absl::StatusOr<subtle::HashType> ToSubtleHashType(
    AesCtrHmacStreamingParameters::HashType hash_type) {
  switch (hash_type) {
    case AesCtrHmacStreamingParameters::HashType::kSha1:
      return subtle::HashType::SHA1;
    case AesCtrHmacStreamingParameters::HashType::kSha256:
      return subtle::HashType::SHA256;
    case AesCtrHmacStreamingParameters::HashType::kSha512:
      return subtle::HashType::SHA512;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Unsupported hash type");
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<StreamingAead>> NewAesCtrHmacStreaming(
    const AesCtrHmacStreamingKey& key) {
  ABSL_ASSIGN_OR_RETURN(subtle::HashType hkdf_algo,
                        ToSubtleHashType(key.GetParameters().HkdfHashType()));
  ABSL_ASSIGN_OR_RETURN(subtle::HashType tag_algo,
                        ToSubtleHashType(key.GetParameters().HmacHashType()));
  subtle::AesCtrHmacStreaming::Params params;
  params.ikm = key.GetInitialKeyMaterial(GetPartialKeyAccess())
                   .Get(InsecureSecretKeyAccess::Get());
  params.hkdf_algo = hkdf_algo;
  params.key_size = key.GetParameters().DerivedKeySizeInBytes();
  params.ciphertext_segment_size =
      key.GetParameters().CiphertextSegmentSizeInBytes();
  params.ciphertext_offset = 0;
  params.tag_algo = tag_algo;
  params.tag_size = key.GetParameters().HmacTagSizeInBytes();
  return subtle::AesCtrHmacStreaming::New(std::move(params));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
