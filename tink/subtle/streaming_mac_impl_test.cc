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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/mac/internal/stateful_mac.h"
#include "tink/output_stream_with_result.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::SecretData;
using ::crypto::tink::util::SecretDataFromStringView;
using ::testing::HasSubstr;

// A dummy implementation of Stateful Mac interface.
// An instance of DummyStatefulMac can be identified by a name specified
// as a parameter of the constructor.
// Over the same inputs, the DummyStatefulMac and DummyMac should give the same
// output; DummyStatefulMac builds and internal_state_ and calls DummyMac.
class DummyStatefulMac : public internal::StatefulMac {
 public:
  explicit DummyStatefulMac(const std::string& mac_name)
      : mac_name_(absl::StrCat("DummyMac:", mac_name)), buffer_("") {}

  absl::Status Update(absl::string_view data) override {
    absl::StrAppend(&buffer_, data);
    return absl::OkStatus();
  }
  absl::StatusOr<SecretData> FinalizeAsSecretData() override {
    return SecretDataFromStringView(absl::StrCat(
        mac_name_.size(), ":", buffer_.size(), ":", mac_name_, buffer_));
  }

 private:
  std::string mac_name_;
  std::string buffer_;
};

class DummyStatefulMacFactory : public internal::StatefulMacFactory {
 public:
  DummyStatefulMacFactory() = default;
  ~DummyStatefulMacFactory() override = default;

  // Constructs a StatefulMac using the DummyStatefulMac, which creates
  // returns a MAC of the header concatenated with the plaintext.
  absl::StatusOr<std::unique_ptr<internal::StatefulMac>> Create()
      const override {
    return std::unique_ptr<internal::StatefulMac>(
        absl::make_unique<DummyStatefulMac>("streaming mac:"));
  }
};

// A helper for creating an OutputStreamWithResult<std::string>,
// used for test validation for mac computation.
std::unique_ptr<OutputStreamWithResult<std::string>>
GetComputeMacOutputStream() {
  auto mac_factory = std::unique_ptr<internal::StatefulMacFactory>(
      absl::make_unique<DummyStatefulMacFactory>());
  auto streaming_mac =
      absl::make_unique<StreamingMacImpl>(std::move(mac_factory));
  absl::StatusOr<std::unique_ptr<OutputStreamWithResult<std::string>>>
      stream_status = streaming_mac->NewComputeMacOutputStream();
  EXPECT_THAT(stream_status, IsOk());
  return std::move(*stream_status);
}

// A helper for creating an OutputStreamWithResult<util::Status>,
// used for test validation for mac verification.
std::unique_ptr<OutputStreamWithResult<absl::Status>> GetVerifyMacOutputStream(
    std::string expected_mac) {
  auto mac_factory = std::unique_ptr<internal::StatefulMacFactory>(
      absl::make_unique<DummyStatefulMacFactory>());
  auto streaming_mac =
      absl::make_unique<StreamingMacImpl>(std::move(mac_factory));
  absl::StatusOr<std::unique_ptr<OutputStreamWithResult<util::Status>>>
      stream_status = streaming_mac->NewVerifyMacOutputStream(expected_mac);
  EXPECT_THAT(stream_status, IsOk());
  return std::move(*stream_status);
}

TEST(StreamingMacImplTest, ComputeEmptyMac) {
  std::string expected_mac = "23:0:DummyMac:streaming mac:";
  auto output_stream = GetComputeMacOutputStream();

  // Close stream and check result
  auto close_status = output_stream->CloseAndGetResult();
  EXPECT_THAT(close_status, IsOk());
  EXPECT_EQ(*close_status, expected_mac);
}

TEST(StreamingMacImplTest, ComputeSmallMac) {
  std::string text = "I am a small message";
  std::string expected_mac =
      "23:20:DummyMac:streaming mac:I am a small message";
  auto output_stream = GetComputeMacOutputStream();

  // Write to the ComputeMacOutputStream
  auto status = test::WriteToStream(output_stream.get(), text, false);
  EXPECT_THAT(status, IsOk());
  EXPECT_EQ(output_stream->Position(), text.size());

  // Close stream and check result
  auto close_status = output_stream->CloseAndGetResult();
  EXPECT_THAT(close_status, IsOk());
  EXPECT_EQ(*close_status, expected_mac);
}

TEST(StreamingMacImplTest, ComputeRandMac) {
  std::vector<int> text_sizes = {0, 10, 100, 1000, 10000, 1000000};

  for (auto text_size : text_sizes) {
    std::string text = Random::GetRandomBytes(text_size);
    std::string expected_mac =
        "23:" + std::to_string(text_size) + ":DummyMac:streaming mac:" + text;
    auto output_stream = GetComputeMacOutputStream();

    // Write to the ComputeMacOutputStream
    auto status = test::WriteToStream(output_stream.get(), text, false);
    EXPECT_THAT(status, IsOk());
    EXPECT_EQ(output_stream->Position(), text.size());

    // Close stream and check result
    auto close_status = output_stream->CloseAndGetResult();
    EXPECT_THAT(close_status, IsOk());
    EXPECT_EQ(*close_status, expected_mac);
  }
}

TEST(StreamingMacImplTest, ComputeCheckStreamPosition) {
  std::string text = "I am a small message";
  auto output_stream = GetComputeMacOutputStream();

  // Check position in first buffer returned by Next();
  void* buffer;
  absl::StatusOr<int> next_result = output_stream->Next(&buffer);
  EXPECT_THAT(next_result, IsOk());
  int buffer_size = *next_result;
  EXPECT_EQ(buffer_size, output_stream->Position());

  // Check position after calling BackUp
  output_stream->BackUp(10);
  EXPECT_EQ(buffer_size - 10, output_stream->Position());
}

TEST(StreamingMacImplTest, ComputeCloseTwiceError) {
  auto output_stream = GetComputeMacOutputStream();

  // Close stream
  auto close_status = output_stream->CloseAndGetResult();

  // Try closing the stream again.
  auto reclose_status = output_stream->Close();
  EXPECT_FALSE(reclose_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, reclose_status.code());
}

TEST(StreamingMacImplTest, VerifyEmptyMac) {
  std::string expected_mac = "23:0:DummyMac:streaming mac:";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Close stream and check result
  auto close_status = output_stream->CloseAndGetResult();
  EXPECT_THAT(close_status, IsOk());
}

TEST(StreamingMacImplTest, VerifySmallMac) {
  std::string text = "I am a small message";
  std::string expected_mac =
      "23:20:DummyMac:streaming mac:I am a small message";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Write to the VerifyMacOutputStream
  auto status = test::WriteToStream(output_stream.get(), text, false);
  EXPECT_THAT(status, IsOk());
  EXPECT_EQ(output_stream->Position(), text.size());

  // Close stream and check result
  auto close_status = output_stream->CloseAndGetResult();
  EXPECT_THAT(close_status, IsOk());
}

TEST(StreamingMacImplTest, VerifyEmptyMacFail) {
  std::string expected_mac = "23:1:DummyMac:streaming mac:";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Close stream and check result
  EXPECT_THAT(
      output_stream->CloseAndGetResult(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Incorrect MAC")));
}

TEST(StreamingMacImplTest, VerifySmallMacFail) {
  std::string text = "I am a small message";
  std::string expected_mac = "23:20:DummyMac:streaming mac:I am wrong message";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Write to the VerifyMacOutputStream
  auto status = test::WriteToStream(output_stream.get(), text, false);
  EXPECT_THAT(status, IsOk());
  EXPECT_EQ(output_stream->Position(), text.size());

  // Close stream and check result
  EXPECT_THAT(
      output_stream->CloseAndGetResult(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("Invalid MAC")));
}

TEST(StreamingMacImplTest, VerifyRandMac) {
  std::vector<int> text_sizes = {0, 10, 100, 1000, 10000, 1000000};

  for (auto text_size : text_sizes) {
    std::string text = Random::GetRandomBytes(text_size);
    std::string expected_mac =
        "23:" + std::to_string(text_size) + ":DummyMac:streaming mac:" + text;
    auto output_stream = GetVerifyMacOutputStream(expected_mac);

    // Write to the VerifyMacOutputStream
    auto status = test::WriteToStream(output_stream.get(), text, false);
    EXPECT_THAT(status, IsOk());
    EXPECT_EQ(output_stream->Position(), text.size());

    // Close stream and check result
    auto close_status = output_stream->CloseAndGetResult();
    EXPECT_THAT(close_status, IsOk());
  }
}

TEST(StreamingMacImplTest, VerifyCheckStreamPosition) {
  std::string text = "I am a small message";
  std::string expected_mac = "23:1:DummyMac:streaming mac:";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Check position in first buffer returned by Next();
  void* buffer;
  absl::StatusOr<int> next_result = output_stream->Next(&buffer);
  EXPECT_THAT(next_result, IsOk());
  int buffer_size = *next_result;
  EXPECT_EQ(buffer_size, output_stream->Position());

  // Check position after calling BackUp
  output_stream->BackUp(10);
  EXPECT_EQ(buffer_size - 10, output_stream->Position());
}

TEST(StreamingMacImplTest, VerifyCloseTwiceError) {
  std::string expected_mac = "23:0:DummyMac:streaming mac:";
  auto output_stream = GetVerifyMacOutputStream(expected_mac);

  // Close stream
  auto close_status = output_stream->CloseAndGetResult();

  // Try closing the stream again.
  auto reclose_status = output_stream->Close();
  EXPECT_FALSE(reclose_status.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, reclose_status.code());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
