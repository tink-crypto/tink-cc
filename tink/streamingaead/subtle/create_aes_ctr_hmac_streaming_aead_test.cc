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

#include "tink/streamingaead/subtle/create_aes_ctr_hmac_streaming_aead.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "tink/input_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key.h"
#include "tink/streamingaead/internal/testing/aes_ctr_hmac_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::internal::CreateAesCtrHmacStreamingTestVectors;
using ::crypto::tink::internal::StreamingAeadTestVector;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using CreateAesCtrHmacStreamingAeadTest =
    TestWithParam<StreamingAeadTestVector>;

INSTANTIATE_TEST_SUITE_P(CreateAesCtrHmacStreamingAeadTest,
                         CreateAesCtrHmacStreamingAeadTest,
                         ValuesIn(CreateAesCtrHmacStreamingTestVectors()));

TEST_P(CreateAesCtrHmacStreamingAeadTest, DecryptTestVectors) {
  const StreamingAeadTestVector& param = GetParam();
  const auto* key = dynamic_cast<const AesCtrHmacStreamingKey*>(
      param.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      CreateAesCtrHmacStreamingAead(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  auto ct_source = std::make_unique<util::IstreamInputStream>(
      std::make_unique<std::stringstream>(param.ciphertext));
  absl::StatusOr<std::unique_ptr<InputStream>> plaintext_stream =
      (*streaming_aead)
          ->NewDecryptingStream(std::move(ct_source), param.associated_data);
  ASSERT_THAT(plaintext_stream, IsOk());

  EXPECT_THAT(
      ReadBytesFromStream(param.plaintext.size(), plaintext_stream->get()),
      IsOkAndHolds(param.plaintext));
  EXPECT_THAT(ReadBytesFromStream(1, plaintext_stream->get()),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST_P(CreateAesCtrHmacStreamingAeadTest, EncryptThenDecrypt) {
  const StreamingAeadTestVector& param = GetParam();
  const auto* key = dynamic_cast<const AesCtrHmacStreamingKey*>(
      param.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      CreateAesCtrHmacStreamingAead(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(streaming_aead->get(), streaming_aead->get(),
                                 param.plaintext, param.associated_data,
                                 /*ciphertext_offset=*/0),
              IsOk());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
