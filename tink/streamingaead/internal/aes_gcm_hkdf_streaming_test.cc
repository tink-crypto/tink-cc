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

#include "tink/streamingaead/internal/aes_gcm_hkdf_streaming.h"

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
#include "tink/internal/fips_utils.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

using AesGcmHkdfStreamingTest = TestWithParam<StreamingAeadTestVector>;

INSTANTIATE_TEST_SUITE_P(AesGcmHkdfStreamingTest, AesGcmHkdfStreamingTest,
                         ValuesIn(CreateAesGcmHkdfStreamingTestVectors()));

TEST_P(AesGcmHkdfStreamingTest, DecryptTestVectors) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& param = GetParam();
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      param.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      NewAesGcmHkdfStreaming(*key);
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

TEST_P(AesGcmHkdfStreamingTest, DecryptTestVectorsRandomAccessStream) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& param = GetParam();
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      param.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      NewAesGcmHkdfStreaming(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  auto ct_source = std::make_unique<TestRandomAccessStream>(param.ciphertext);
  absl::StatusOr<std::unique_ptr<RandomAccessStream>> plaintext_stream =
      (*streaming_aead)
          ->NewDecryptingRandomAccessStream(std::move(ct_source),
                                            param.associated_data);
  ASSERT_THAT(plaintext_stream, IsOk());

  std::string decrypted;
  EXPECT_THAT(ReadAllFromRandomAccessStream(plaintext_stream->get(), decrypted),
              StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(decrypted, param.plaintext);
}

TEST_P(AesGcmHkdfStreamingTest, EncryptThenDecrypt) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& param = GetParam();
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      param.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      NewAesGcmHkdfStreaming(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  EXPECT_THAT(EncryptThenDecrypt(streaming_aead->get(), streaming_aead->get(),
                                 param.plaintext, param.associated_data,
                                 /*ciphertext_offset=*/0),
              IsOk());
}

TEST(AesGcmHkdfStreamingTest, FipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& test_vector =
      GetAesGcmHkdfStreamingTestVector(16);
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      test_vector.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  EXPECT_THAT(NewAesGcmHkdfStreaming(*key),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
