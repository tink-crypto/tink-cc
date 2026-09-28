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

#ifndef TINK_AEAD_INTERNAL_DUMMY_ZERO_COPY_AEAD_H_
#define TINK_AEAD_INTERNAL_DUMMY_ZERO_COPY_AEAD_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {

// A dummy implementation of ZeroCopyAead-interface.
// An instance of DummyZeroCopyAead can be identified by a name specified
// as a parameter of the constructor.
// The implementation produces the same ciphertexts as test::DummyAead for
// associated_data sizes up to max_associated_data_size.
class DummyZeroCopyAead : public ZeroCopyAead {
 public:
  explicit DummyZeroCopyAead(absl::string_view aead_name,
                             size_t max_associated_data_size = 1024)
      : aead_(aead_name), max_associated_data_size_(max_associated_data_size) {}

  int64_t MaxEncryptionSize(int64_t plaintext_size) const override {
    absl::StatusOr<std::string> sample_ciphertext =
        aead_.Encrypt(std::string(plaintext_size, 'a'),
                      std::string(max_associated_data_size_, 'a'));
    ABSL_CHECK_OK(sample_ciphertext);
    return sample_ciphertext->size();
  }

  absl::StatusOr<int64_t> Encrypt(absl::string_view plaintext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    ABSL_RETURN_IF_ERROR(CheckAssociatedDataSize(associated_data));
    ABSL_ASSIGN_OR_RETURN(std::string ciphertext,
                          aead_.Encrypt(plaintext, associated_data));
    ABSL_RETURN_IF_ERROR(CopyToBuffer(ciphertext, buffer));
    return ciphertext.size();
  }

  int64_t MaxDecryptionSize(int64_t ciphertext_size) const override {
    absl::StatusOr<std::string> smallest_ciphertext = aead_.Encrypt("", "");
    ABSL_CHECK_OK(smallest_ciphertext);
    return std::max<int64_t>(
        0, ciphertext_size - static_cast<int64_t>(smallest_ciphertext->size()));
  }

  absl::StatusOr<int64_t> Decrypt(absl::string_view ciphertext,
                                  absl::string_view associated_data,
                                  absl::Span<char> buffer) const override {
    ABSL_RETURN_IF_ERROR(CheckAssociatedDataSize(associated_data));
    ABSL_ASSIGN_OR_RETURN(std::string plaintext,
                          aead_.Decrypt(ciphertext, associated_data));
    ABSL_RETURN_IF_ERROR(CopyToBuffer(plaintext, buffer));
    return plaintext.size();
  }

 private:
  absl::Status CheckAssociatedDataSize(
      absl::string_view associated_data) const {
    if (associated_data.size() > max_associated_data_size_) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Associated data too large for DummyZeroCopyAead.");
    }
    return absl::OkStatus();
  }

  static absl::Status CopyToBuffer(absl::string_view data,
                                   absl::Span<char> buffer) {
    if (buffer.size() < data.size()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Buffer too small.");
    }
    absl::c_copy(data, buffer.data());
    return absl::OkStatus();
  }

  crypto::tink::test::DummyAead aead_;
  size_t max_associated_data_size_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_DUMMY_ZERO_COPY_AEAD_H_
