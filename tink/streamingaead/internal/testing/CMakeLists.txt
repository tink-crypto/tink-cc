tink_module(streamingaead::internal::testing)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_test_vectors
  SRCS
    aes_ctr_hmac_streaming_test_vectors.cc
    aes_ctr_hmac_streaming_test_vectors.h
  DEPS
    tink::streamingaead::internal::testing::streamingaead_test_vector
    absl::absl_check
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME streamingaead_test_vector
  SRCS
    streamingaead_test_vector.h
  DEPS
    absl::string_view
    tink::streamingaead::streaming_aead_key
  TESTONLY
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_test_vectors
  SRCS
    aes_gcm_hkdf_streaming_test_vectors.cc
    aes_gcm_hkdf_streaming_test_vectors.h
  DEPS
    tink::streamingaead::internal::testing::aes_ctr_hmac_streaming_test_vectors
    tink::streamingaead::internal::testing::streamingaead_test_vector
    absl::absl_check
    absl::strings
    absl::string_view
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::streamingaead::aes_gcm_hkdf_streaming_key
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    tink::util::statusor
    tink::util::test_util
  TESTONLY
)
