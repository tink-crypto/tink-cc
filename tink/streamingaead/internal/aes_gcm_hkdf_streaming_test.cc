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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_macros.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/internal/fips_utils.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_parameters.h"
#include "tink/streamingaead/internal/testing/aes_gcm_hkdf_streaming_test_vectors.h"
#include "tink/streamingaead/internal/testing/streamingaead_test_vector.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::Ne;
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

TEST_P(AesGcmHkdfStreamingTest, EncryptThenDecryptLongPlaintext) {
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

  // 10 KB plaintext spans many segments for all test vector segment sizes.
  std::string plaintext = subtle::Random::GetRandomBytes(10000);
  EXPECT_THAT(EncryptThenDecrypt(streaming_aead->get(), streaming_aead->get(),
                                 plaintext, param.associated_data,
                                 /*ciphertext_offset=*/0),
              IsOk());
}

TEST_P(AesGcmHkdfStreamingTest, EncryptUsesFreshSaltPerStream) {
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

  StreamingAead& aead = **streaming_aead;
  auto encrypt_empty = [&aead, &param]() -> absl::StatusOr<std::string> {
    auto ct_stream = std::make_unique<std::stringstream>();
    std::stringbuf* ct_buf = ct_stream->rdbuf();
    ABSL_ASSIGN_OR_RETURN(
        std::unique_ptr<OutputStream> enc_stream,
        aead.NewEncryptingStream(
            std::make_unique<util::OstreamOutputStream>(std::move(ct_stream)),
            param.associated_data));
    ABSL_RETURN_IF_ERROR(enc_stream->Close());
    return ct_buf->str();
  };

  absl::StatusOr<std::string> ct1 = encrypt_empty();
  ASSERT_THAT(ct1, IsOk());
  absl::StatusOr<std::string> ct2 = encrypt_empty();
  ASSERT_THAT(ct2, IsOk());

  // AES-GCM-HKDF header format:
  // header_size (1 byte) || salt (derived_key_size bytes) ||
  // nonce_prefix (7 bytes).
  const int derived_key_size = key->GetParameters().DerivedKeySizeInBytes();
  const int expected_header_size = 1 + derived_key_size + 7;
  ASSERT_THAT(ct1->size(), Ge(static_cast<size_t>(expected_header_size)));
  ASSERT_THAT(ct2->size(), Ge(static_cast<size_t>(expected_header_size)));
  EXPECT_THAT(static_cast<int>(static_cast<uint8_t>((*ct1)[0])),
              Eq(expected_header_size));
  EXPECT_THAT(static_cast<int>(static_cast<uint8_t>((*ct2)[0])),
              Eq(expected_header_size));

  absl::string_view salt1 = absl::string_view(*ct1).substr(1, derived_key_size);
  absl::string_view salt2 = absl::string_view(*ct2).substr(1, derived_key_size);
  EXPECT_THAT(salt1, Ne(salt2));
}

TEST(AesGcmHkdfStreamingTest, NewEncryptingStreamNullDestinationFails) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& test_vector =
      GetAesGcmHkdfStreamingTestVector(16);
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      test_vector.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      NewAesGcmHkdfStreaming(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  EXPECT_THAT(
      (*streaming_aead)->NewEncryptingStream(nullptr, "some associated data"),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("non-null")));
}

TEST(AesGcmHkdfStreamingTest, SizeIsUnauthenticated) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  const StreamingAeadTestVector& test_vector =
      GetAesGcmHkdfStreamingTestVector(16);
  const auto* key = dynamic_cast<const AesGcmHkdfStreamingKey*>(
      test_vector.streamingaead_key.get());
  ASSERT_THAT(key, NotNull());

  absl::StatusOr<std::unique_ptr<StreamingAead>> streaming_aead =
      NewAesGcmHkdfStreaming(*key);
  ASSERT_THAT(streaming_aead, IsOk());

  std::string associated_data = "some associated data";
  // The header is 24 = 0x18 bytes for this key and Tink verifies that the
  // ciphertext starts with 0x18 in the first byte.
  std::string wrong_ciphertext =
      absl::StrCat(test::HexDecodeOrDie("18"), std::string(92, 'a'));
  absl::StatusOr<std::unique_ptr<RandomAccessStream>> plaintext_stream =
      (*streaming_aead)
          ->NewDecryptingRandomAccessStream(
              std::make_unique<TestRandomAccessStream>(wrong_ciphertext),
              associated_data);
  ASSERT_THAT(plaintext_stream, IsOk());
  // 93 bytes of ciphertext with 64-byte segments: 24-byte header + two 16-byte
  // tags leaves 37 bytes of plaintext.
  EXPECT_THAT((*plaintext_stream)->size(), IsOkAndHolds(Eq(37)));
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
