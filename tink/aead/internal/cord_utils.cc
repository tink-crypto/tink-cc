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

#include "tink/aead/internal/cord_utils.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/log/absl_check.h"
#include "absl/strings/cord.h"
#include "absl/strings/cord_buffer.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace crypto {
namespace tink {
namespace internal {

absl::Span<char> CordWriter::NextWriteBuffer() {
  if (!current_buffer_span_.empty() || max_size_ == 0) {
    return current_buffer_span_;
  }
  size_t to_allocate = max_size_ - written_so_far_;
  if (to_allocate == 0) {
    return current_buffer_span_;
  }
  current_buffer_ = absl::CordBuffer::CreateWithCustomLimit(
      absl::CordBuffer::kCustomLimit, to_allocate);
  // The buffer capacity can be more than the requested, so we cap the span.
  current_buffer_span_ =
      absl::MakeSpan(current_buffer_.data(),
                     std::min(to_allocate, current_buffer_.capacity()));
  return current_buffer_span_;
}

void CordWriter::Advance(int size) {
  ABSL_CHECK_LE(written_so_far_ + size, max_size_);
  written_so_far_ += size;
  current_buffer_.IncreaseLengthBy(size);
  current_buffer_span_.remove_prefix(size);
  if (current_buffer_span_.empty()) {
    destination_.Append(std::move(current_buffer_));
    current_buffer_ = absl::CordBuffer();
  }
}

void CordWriter::Write(absl::string_view data) {
  ABSL_CHECK_LE(data.size(), max_size_ + current_buffer_span_.size());
  while (!data.empty()) {
    absl::Span<char> buffer = NextWriteBuffer().subspan(0, data.size());
    std::memcpy(buffer.data(), data.data(), buffer.size());
    Advance(buffer.size());
    data.remove_prefix(buffer.size());
  }
}

absl::Cord CordWriter::data() && {
  if (!current_buffer_span_.empty()) {
    destination_.Append(std::move(current_buffer_));
  }
  return std::move(destination_);
}

absl::string_view CordReader::Peek() {
  if (current_chunk_.empty() && next_chunk_it_ != cord_.chunk_end()) {
    current_chunk_ = *next_chunk_it_;
    ++next_chunk_it_;
  }
  return current_chunk_;
}

void CordReader::Skip(size_t size) {
  size = std::min(size, Available());
  position_ += size;
  while (size > 0) {
    // Load the next chunk into current_chunk_ if needed; ignore the return
    // value.
    Peek();
    auto to_skip = std::min(size, current_chunk_.size());
    current_chunk_.remove_prefix(to_skip);
    size -= to_skip;
  }
}

void CordReader::ReadN(size_t size, char* /*absl_nonnull - not yet supported*/ dest) {
  // Cannot read more than Available().
  ABSL_CHECK_LE(size, Available());
  while (size > 0) {
    absl::string_view chunk = Peek().substr(0, size);
    std::memcpy(dest, chunk.data(), chunk.size());
    dest += chunk.size();
    Skip(chunk.size());
    size -= std::min(size, chunk.size());
  }
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
