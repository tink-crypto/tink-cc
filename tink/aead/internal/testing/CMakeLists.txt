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

tink_cc_library(
  NAME aes_eax_test_vectors
  SRCS
    aes_eax_test_vectors.cc
    aes_eax_test_vectors.h
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
    tink::aead::aes_eax_key
    tink::aead::aes_eax_parameters
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME aes_ctr_hmac_aead_test_vectors
  SRCS
    aes_ctr_hmac_aead_test_vectors.cc
    aes_ctr_hmac_aead_test_vectors.h
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
    tink::aead::aes_ctr_hmac_aead_key
    tink::aead::aes_ctr_hmac_aead_parameters
    tink::subtle::aes_ctr_boringssl
    tink::subtle::common_enums
    tink::subtle::encrypt_then_authenticate
    tink::subtle::hmac_boringssl
    tink::util::secret_data
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME aes_gcm_siv_test_vectors
  SRCS
    aes_gcm_siv_test_vectors.cc
    aes_gcm_siv_test_vectors.h
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
    tink::aead::aes_gcm_siv_key
    tink::aead::aes_gcm_siv_parameters
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME x_aes_gcm_test_vectors
  SRCS
    x_aes_gcm_test_vectors.cc
    x_aes_gcm_test_vectors.h
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
    tink::aead::x_aes_gcm_key
    tink::aead::x_aes_gcm_parameters
    tink::aead::internal::cord_x_aes_gcm_boringssl
    tink::util::test_util
  TESTONLY
)




