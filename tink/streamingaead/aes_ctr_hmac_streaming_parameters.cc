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

#include "tink/streamingaead/aes_ctr_hmac_streaming_parameters.h"

#include <cstdint>
#include <map>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/parameters.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetKeySizeInBytes(int key_size) {
  key_size_in_bytes_ = key_size;
  return *this;
}

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetDerivedKeySizeInBytes(
    int derived_key_size) {
  derived_key_size_in_bytes_ = derived_key_size;
  return *this;
}

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetHkdfHashType(HashType hash_type) {
  hkdf_hash_type_ = hash_type;
  return *this;
}

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetHmacHashType(HashType hash_type) {
  hmac_hash_type_ = hash_type;
  return *this;
}

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetHmacTagSizeInBytes(int tag_size) {
  tag_size_in_bytes_ = tag_size;
  return *this;
}

AesCtrHmacStreamingParameters::Builder&
AesCtrHmacStreamingParameters::Builder::SetCiphertextSegmentSizeInBytes(
    int segment_size) {
  segment_size_in_bytes_ = segment_size;
  return *this;
}

util::StatusOr<AesCtrHmacStreamingParameters>
AesCtrHmacStreamingParameters::Builder::Build() {
  if (!key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key size must be set.");
  }
  if (!derived_key_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Derived key size must be set.");
  }
  if (!hkdf_hash_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HKDF hash type must be set.");
  }
  if (!hmac_hash_type_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HMAC hash type must be set.");
  }
  if (!tag_size_in_bytes_.has_value()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HMAC tag size must be set.");
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
  // CiphertextSegmentSize > DerivedKeySize + HmacTagSize + len(Header)
  // https://developers.google.com/tink/streaming-aead/aes_ctr_hmac_streaming#splitting_the_message
  int min_segment_size = *derived_key_size_in_bytes_ + *tag_size_in_bytes_ + 9;
  if (*segment_size_in_bytes_ < min_segment_size) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Ciphertext segment size must be at least ",
                     min_segment_size, " bytes"));
  }

  if (*tag_size_in_bytes_ < 10) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Tag size is too small.");
  }
  static const std::map<AesCtrHmacStreamingParameters::HashType, uint32_t>*
      max_tag_size =
          new std::map<AesCtrHmacStreamingParameters::HashType, uint32_t>(
              {{AesCtrHmacStreamingParameters::HashType::kSha1, 20},
               {AesCtrHmacStreamingParameters::HashType::kSha256, 32},
               {AesCtrHmacStreamingParameters::HashType::kSha512, 64}});
  // Re-purposing max_tag_size map to check that HKDF hash type is supported.
  if (max_tag_size->find(*hkdf_hash_type_) == max_tag_size->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HKDF hash type not supported.");
  }
  if (max_tag_size->find(*hmac_hash_type_) == max_tag_size->end()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "HMAC hash type not supported.");
  }
  if (*tag_size_in_bytes_ > max_tag_size->at(*hmac_hash_type_)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Tag size is too big for given ", *hmac_hash_type_,
                     " , got ", *tag_size_in_bytes_, " bytes."));
  }

  return AesCtrHmacStreamingParameters(
      *key_size_in_bytes_, *derived_key_size_in_bytes_, *hkdf_hash_type_,
      *hmac_hash_type_, *tag_size_in_bytes_, *segment_size_in_bytes_);
}

bool AesCtrHmacStreamingParameters::operator==(const Parameters& other) const {
  const AesCtrHmacStreamingParameters* that =
      dynamic_cast<const AesCtrHmacStreamingParameters*>(&other);
  if (that == nullptr) {
    return false;
  }
  if (key_size_in_bytes_ != that->key_size_in_bytes_) {
    return false;
  }
  if (derived_key_size_in_bytes_ != that->derived_key_size_in_bytes_) {
    return false;
  }
  if (hkdf_hash_type_ != that->hkdf_hash_type_) {
    return false;
  }
  if (hmac_hash_type_ != that->hmac_hash_type_) {
    return false;
  }
  if (tag_size_in_bytes_ != that->tag_size_in_bytes_) {
    return false;
  }
  if (segment_size_in_bytes_ != that->segment_size_in_bytes_) {
    return false;
  }
  return true;
}

}  // namespace tink
}  // namespace crypto
