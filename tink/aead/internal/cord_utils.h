// Copyright 2024 Google LLC
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

#ifndef TINK_AEAD_INTERNAL_CORD_UTILS_H_
#define TINK_AEAD_INTERNAL_CORD_UTILS_H_

#include <cstdint>
#include <cstring>

#include "absl/base/nullability.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace crypto {
namespace tink {
namespace internal {

// Helper class that allows writing to a Cord up to a given size.
//
// Usage:
//   CordWriter writer(max_size);
//   writer.Write(data);
//   // ...
//   // Write some more data.
//   // ...
//   absl::Cord result = std::move(writer).data();
class CordWriter {
 public:
  // Creates a new writer that can write up to `max_size` bytes.
  explicit CordWriter(size_t max_size) : max_size_(max_size) {}

  // Returns a span of the current write buffer; allocates memory if necessary.
  //
  // After `max_size_` bytes have been written, the returned span will be empty.
  // When a new buffer is created, the allocated size is min(max_size_ -
  // written_so_far_, absl::CordBuffer::kCustomLimit). Note that when a
  // absl::CordBuffer of desired capacity absl::CordBuffer::kCustomLimit is
  // generated, the actual available capacity is slightly smaller (13 bytes less
  // at the time of writing).
  absl::Span<char> NextWriteBuffer();

  // Advances the writer by `size` bytes; `size` must be less or equal to the
  // size of the buffer returned by the last call to NextWriteBuffer().
  //
  // REQUIRES: current_buffer_span_.size() >= size
  void Advance(int size);

  // Writes `data` to the destination.
  //
  // REQUIRES: data.size() <= max_size_ - written_so_far_
  void Write(absl::string_view data);

  // Flushes the writer and "steals" the cord.
  absl::Cord data() &&;

 private:
  absl::Cord destination_;

  // Current buffer.
  absl::CordBuffer current_buffer_;
  absl::Span<char> current_buffer_span_;

  // Total maximum bytes to be written to the Cord.
  const size_t max_size_;
  // Keeps track of the number of bytes written so far.
  size_t written_so_far_ = 0;
};

// Helper class that allows reading from a Cord.
//
// Usage:
//   CordReader reader(cord);
//   while (reader.Available() > 0) {
//     absl::string_view chunk = reader.Peek();
//     // ...
//     reader.Skip(chunk.size());
//   }
class CordReader {
 public:
  explicit CordReader(absl::Cord& cord)
      : cord_(cord), next_chunk_it_(cord_.chunk_begin()) {}

  // Returns the number of bytes available to be read.
  size_t Available() const { return cord_.size() - position_; }

  // Returns the next chunk in the cord. The returned string_view is valid until
  // the next call to Skip().
  // Multiple calls to Peek() will return the same chunk, until Skip() is
  // called.
  absl::string_view Peek();

  // Skips `size` bytes in the cord. `size` is allowed to be larger than
  // Available().
  void Skip(size_t size);

  // Read `size` bytes into `dest`.
  void ReadN(size_t size, absl::Nonnull<char*> dest);

 private:
  absl::Cord& cord_;
  int64_t position_ = 0;

  absl::Cord::ChunkIterator next_chunk_it_;
  // Current chunk.
  absl::string_view current_chunk_ = {};
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_CORD_UTILS_H_
