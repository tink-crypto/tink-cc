tink_module(aead::internal::testing)

tink_cc_library(
  NAME aead_test_vector
  SRCS
    aead_test_vector.h
  DEPS
    absl::string_view
    tink::aead::aead_key
  TESTONLY
)

tink_cc_library(
  NAME aes_gcm_test_vectors
  SRCS
    aes_gcm_test_vectors.cc
    aes_gcm_test_vectors.h
  DEPS
    tink::aead::internal::testing::aead_test_vector
    absl::absl_check
    absl::no_destructor
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_parameters
    tink::util::test_util
  TESTONLY
)
