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

#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"

#include <cstdint>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

AesGcmHkdfStreamingParameters::Builder&
AesGcmHkdfStreamingParameters::Builder::SetKeySizeInBytes(int key_size) {
  key_size_in_bytes_ = key_size;
  return *this;
}

AesGcmHkdfStreamingParameters::Builder&
AesGcmHkdfStreamingParameters::Builder::SetDerivedKeySizeInBytes(
    int derived_key_size) {
  derived_key_size_in_bytes_ = derived_key_size;
  return *this;
}

AesGcmHkdfStreamingParameters::Builder&
AesGcmHkdfStreamingParameters::Builder::SetHashType(HashType hash_type) {
  hash_type_ = hash_type;
  return *this;
}

AesGcmHkdfStreamingParameters::Builder&
AesGcmHkdfStreamingParameters::Builder::SetCiphertextSegmentSizeInBytes(
    int segment_size) {
  segment_size_in_bytes_ = segment_size;
  return *this;
}

absl::StatusOr<AesGcmHkdfStreamingParameters>
AesGcmHkdfStreamingParameters::Builder::Build() {
  if (!key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size must be set.");
  }
  if (!derived_key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Derived key size must be set.");
  }
  if (!hash_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Hash type must be set.");
  }
  if (!segment_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Ciphertext segment size must be set.");
  }

  if (*derived_key_size_in_bytes_ != 16 && *derived_key_size_in_bytes_ != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Derived key size must be either 16 or 32 bytes");
  }
  if (*key_size_in_bytes_ < *derived_key_size_in_bytes_) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size must be at least the derived key size.");
  }
  // CiphertextSegmentSize > DerivedKeySize + 24
  // https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming#key_and_parameters
  int min_segment_size = *derived_key_size_in_bytes_ + 24;
  if (*segment_size_in_bytes_ < min_segment_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Ciphertext segment size must be at least ",
                     min_segment_size, " bytes"));
  }
  // Ensure that maximum ciphertext segment size is consistent with Tink Java.
  // Only reachable if sizeof(int) > 4 bytes.
  if (*segment_size_in_bytes_ > INT32_MAX) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Ciphertext segment size must be at most ",
                                     INT32_MAX, " bytes"));
  }

  static const auto* kSupportedHashTypes =
      new absl::flat_hash_set<AesGcmHkdfStreamingParameters::HashType>(
          {AesGcmHkdfStreamingParameters::HashType::kSha1,
           AesGcmHkdfStreamingParameters::HashType::kSha256,
           AesGcmHkdfStreamingParameters::HashType::kSha512});
  if (!kSupportedHashTypes->contains(*hash_type_)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Hash type not supported.");
  }

  return AesGcmHkdfStreamingParameters(*key_size_in_bytes_,
                                       *derived_key_size_in_bytes_, *hash_type_,
                                       *segment_size_in_bytes_);
}

bool AesGcmHkdfStreamingParameters::operator==(const Parameters& other) const {
  const AesGcmHkdfStreamingParameters* that =
      dynamic_cast<const AesGcmHkdfStreamingParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (derived_key_size_in_bytes_ != that->derived_key_size_in_bytes_) {
    return false;
  }
  if (hash_type_ != that->hash_type_) {
    return false;
  }
  if (segment_size_in_bytes_ != that->segment_size_in_bytes_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
