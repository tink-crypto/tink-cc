// Copyright 2019 Google Inc.
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

#ifndef TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_
#define TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_

#include <cstdint>
#include <memory>
#include <vector>

#include "tink/output_stream.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class StreamingAeadEncryptingStream : public OutputStream {
 public:
  // A factory that produces encrypting streams.
  // The returned stream is a wrapper around 'ciphertext_destination',
  // such that any bytes written via the wrapper are AEAD-encrypted
  // by 'segment_encrypter' using 'associated_data' as associated
  // authenticated data.
  static absl::StatusOr<std::unique_ptr<crypto::tink::OutputStream>> New(
      std::unique_ptr<StreamSegmentEncrypter> segment_encrypter,
      std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination);

  // -----------------------
  // Methods of OutputStream-interface implemented by this class.
  absl::StatusOr<int> Next(void** data) override;
  void BackUp(int count) override;
  absl::Status Close() override;
  int64_t Position() const override;

 private:
  StreamingAeadEncryptingStream() = default;
  std::unique_ptr<StreamSegmentEncrypter> segment_encrypter_;
  std::unique_ptr<crypto::tink::OutputStream> ct_destination_;
  std::vector<uint8_t> pt_buffer_;  // plaintext buffer
  std::vector<uint8_t> ct_buffer_;  // ciphertext buffer
  std::vector<uint8_t> pt_to_encrypt_;  // plaintext to be encrypted
  int64_t position_;  // number of plaintext bytes written to this stream
  absl::Status status_;  // status of the stream

  // Counters that describe the state of the data in pt_buffer_.
  int count_backedup_;    // # bytes in pt_buffer_ that were backed up
  int pt_buffer_offset_;  // offset at which *data starts in pt_buffer_

  // Flag that indicates whether the user has obtained a buffer to write
  // the data of the first segment.
  // If true, Next() was not called yet, which implies that neither
  // header has been written to ct_destination_, nor the user had
  // a chance to write any data to this stream.
  bool is_first_segment_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_STREAMING_AEAD_ENCRYPTING_STREAM_H_
