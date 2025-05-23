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

#include "tink/subtle/streaming_mac_impl.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "tink/internal/safe_stringops.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/output_stream_with_result.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
constexpr size_t kBufferSize = 4096;
}

class ComputeMacOutputStream : public OutputStreamWithResult<std::string> {
 public:
  explicit ComputeMacOutputStream(std::unique_ptr<internal::StatefulMac> mac)
      : status_(absl::OkStatus()),
        mac_(std::move(mac)),
        position_(0),
        buffer_position_(0),
        buffer_("") {
    buffer_.resize(kBufferSize);
  }

  absl::StatusOr<int> NextBuffer(void** buffer) override;
  absl::StatusOr<std::string> CloseStreamAndComputeResult() override;
  void BackUp(int count) override;
  int64_t Position() const override { return position_; }

 private:
  void WriteIntoMac();

  absl::Status status_;
  const std::unique_ptr<internal::StatefulMac> mac_;
  int64_t position_;
  int buffer_position_;
  std::string buffer_;
};

absl::StatusOr<std::unique_ptr<OutputStreamWithResult<std::string>>>
StreamingMacImpl::NewComputeMacOutputStream() const {
  absl::StatusOr<std::unique_ptr<internal::StatefulMac>> mac_status =
      mac_factory_->Create();

  if (!mac_status.ok()) {
    return mac_status.status();
  }

  std::unique_ptr<OutputStreamWithResult<std::string>> string_to_return =
      absl::make_unique<ComputeMacOutputStream>(std::move(mac_status.value()));
  return std::move(string_to_return);
}

absl::StatusOr<int> ComputeMacOutputStream::NextBuffer(void** buffer) {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  *buffer = &buffer_[0];
  position_ += kBufferSize;
  buffer_position_ = kBufferSize;
  return buffer_position_;
}

absl::StatusOr<std::string>
ComputeMacOutputStream::CloseStreamAndComputeResult() {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  status_ =
      absl::Status(absl::StatusCode::kFailedPrecondition, "Stream Closed");
  absl::StatusOr<SecretData> result = mac_->FinalizeAsSecretData();
  if (!result.ok()) {
    return result.status();
  }
  return std::string(util::SecretDataAsStringView(*result));
}

void ComputeMacOutputStream::BackUp(int count) {
  count = std::min(count, buffer_position_);
  buffer_position_ -= count;
  position_ -= count;
}

// Writes the data in buffer_ into mac_, and clears buffer_.
void ComputeMacOutputStream::WriteIntoMac() {
  // Remove the suffix of the buffer (all data after buffer_position_).
  status_ = mac_->Update(absl::string_view(buffer_.data(), buffer_position_));

  // Clear the buffer, so that any sensitive information that
  // was written to the buffer cannot be accessed later.
  // Write buffer_position_ number of 0's to the buffer, starting from idx 0.
  buffer_.replace(0, buffer_position_, buffer_position_, 0);
}

class VerifyMacOutputStream : public OutputStreamWithResult<absl::Status> {
 public:
  VerifyMacOutputStream(const std::string& expected,
                        std::unique_ptr<internal::StatefulMac> mac)
      : status_(absl::OkStatus()),
        mac_(std::move(mac)),
        position_(0),
        buffer_position_(0),
        buffer_(""),
        expected_(expected) {
    buffer_.resize(kBufferSize);
  }

  absl::StatusOr<int> NextBuffer(void** buffer) override;

  absl::Status CloseStreamAndComputeResult() override;

  void BackUp(int count) override;
  int64_t Position() const override { return position_; }

 private:
  void WriteIntoMac();

  // Stream status: Initialized as OK, and
  // changed to ERROR:FAILED_PRECONDITION when the stream is closed.
  absl::Status status_;
  std::unique_ptr<internal::StatefulMac> mac_;
  int64_t position_;
  int buffer_position_;
  std::string buffer_;
  std::string expected_;
};

absl::StatusOr<int> VerifyMacOutputStream::NextBuffer(void** buffer) {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  *buffer = &buffer_[0];
  position_ += kBufferSize;
  buffer_position_ = kBufferSize;
  return buffer_position_;
}

absl::Status VerifyMacOutputStream::CloseStreamAndComputeResult() {
  if (!status_.ok()) {
    return status_;
  }
  WriteIntoMac();
  status_ =
      absl::Status(absl::StatusCode::kFailedPrecondition, "Stream Closed");
  absl::StatusOr<SecretData> mac_actual = mac_->FinalizeAsSecretData();
  if (!mac_actual.ok()) {
    return mac_actual.status();
  }
  if (mac_actual->size() != expected_.size()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid MAC size; expected ", expected_.size(), ", got ",
                     mac_actual->size()));
  }
  if (internal::SafeCryptoMemEquals(mac_actual->data(), expected_.data(),
                                    mac_actual->size())) {
    return absl::OkStatus();
  }
  return absl::InvalidArgumentError("Incorrect MAC");
}

void VerifyMacOutputStream::BackUp(int count) {
  count = std::min(count, buffer_position_);
  buffer_position_ -= count;
  position_ -= count;
}

// Writes the data in buffer_ into mac_, and clears buffer_.
void VerifyMacOutputStream::WriteIntoMac() {
  // Remove the suffix of the buffer (all data after buffer_position_).
  status_ = mac_->Update(absl::string_view(buffer_.data(), buffer_position_));

  // Clear the buffer, so that any sensitive information that
  // was written to the buffer cannot be accessed later.
  // Write buffer_position_ number of 0's to the buffer, starting from idx 0.
  buffer_.replace(0, buffer_position_, buffer_position_, 0);
}

absl::StatusOr<std::unique_ptr<OutputStreamWithResult<absl::Status>>>
StreamingMacImpl::NewVerifyMacOutputStream(const std::string& mac_value) const {
  absl::StatusOr<std::unique_ptr<internal::StatefulMac>> mac_status =
      mac_factory_->Create();
  if (!mac_status.ok()) {
    return mac_status.status();
  }
  return std::unique_ptr<OutputStreamWithResult<absl::Status>>(
      absl::make_unique<VerifyMacOutputStream>(mac_value,
                                               std::move(mac_status.value())));
}
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
