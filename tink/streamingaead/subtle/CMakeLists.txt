tink_module(streamingaead::subtle)

tink_cc_library(
  NAME create_aes_ctr_hmac_streaming_aead
  SRCS
    create_aes_ctr_hmac_streaming_aead.cc
    create_aes_ctr_hmac_streaming_aead.h
  DEPS
    absl::statusor
    tink::core::streaming_aead
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::internal::aes_ctr_hmac_streaming
  PUBLIC
)

tink_cc_test(
  NAME create_aes_ctr_hmac_streaming_aead_test
  SRCS
    create_aes_ctr_hmac_streaming_aead_test.cc
  DEPS
    tink::streamingaead::subtle::create_aes_ctr_hmac_streaming_aead
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::input_stream
    tink::core::streaming_aead
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::internal::testing::aes_ctr_hmac_streaming_test_vectors
    tink::streamingaead::internal::testing::streamingaead_test_vector
    tink::subtle::streaming_aead_test_util
    tink::util::input_stream_util
    tink::util::istream_input_stream
)
