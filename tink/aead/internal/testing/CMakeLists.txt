tink_module(aead::internal::testing)

tink_cc_library(
  NAME aead_test_vector
  SRCS
    aead_test_vector.h
  DEPS
    absl::string_view
    tink::aead::aead_key
)

tink_cc_library(
  NAME aes_gcm_test_vectors
  SRCS
    aes_gcm_test_vectors.cc
    aes_gcm_test_vectors.h
  DEPS
    tink::aead::internal::testing::aead_test_vector
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_parameters
    tink::util::test_util
)

tink_cc_library(
  NAME aes_eax_test_vectors
  SRCS
    aes_eax_test_vectors.cc
    aes_eax_test_vectors.h
  DEPS
    tink::aead::internal::testing::aead_test_vector
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
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
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::aes_ctr_hmac_aead_key
    tink::aead::aes_ctr_hmac_aead_parameters
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
    absl::core_headers
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
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
    absl::core_headers
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::x_aes_gcm_key
    tink::aead::x_aes_gcm_parameters
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME chacha20_poly1305_test_vectors
  SRCS
    chacha20_poly1305_test_vectors.cc
    chacha20_poly1305_test_vectors.h
  DEPS
    tink::aead::internal::testing::aead_test_vector
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::chacha20_poly1305_key
    tink::aead::chacha20_poly1305_parameters
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME xchacha20_poly1305_test_vectors
  SRCS
    xchacha20_poly1305_test_vectors.cc
    xchacha20_poly1305_test_vectors.h
  DEPS
    tink::aead::internal::testing::aead_test_vector
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_parameters
    tink::util::test_util
  TESTONLY
)

