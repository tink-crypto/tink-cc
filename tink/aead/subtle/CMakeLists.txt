tink_module(aead::subtle)

tink_cc_library(
  NAME create_aes_ctr_hmac_aead
  SRCS
    create_aes_ctr_hmac_aead.cc
    create_aes_ctr_hmac_aead.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::core::aead
    tink::aead::aes_ctr_hmac_aead_key
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_aes_ctr_hmac_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_aes_ctr_hmac_aead_test
  SRCS
    create_aes_ctr_hmac_aead_test.cc
  DEPS
    tink::aead::subtle::create_aes_ctr_hmac_aead
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::aead
    tink::aead::aes_ctr_hmac_aead_key
    tink::aead::aes_ctr_hmac_aead_parameters
    tink::aead::internal::testing::aead_test_vector
    tink::aead::internal::testing::aes_ctr_hmac_aead_test_vectors
)

tink_cc_library(
  NAME create_chacha20_poly1305_aead
  SRCS
    create_chacha20_poly1305_aead.cc
    create_chacha20_poly1305_aead.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::core::aead
    tink::aead::chacha20_poly1305_key
    tink::aead::internal::aead_from_zero_copy
    tink::aead::internal::zero_copy_aead
    tink::aead::internal::zero_copy_chacha20_poly1305_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_chacha20_poly1305_aead_test
  SRCS
    create_chacha20_poly1305_aead_test.cc
  DEPS
    tink::aead::subtle::create_chacha20_poly1305_aead
    gmock
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::aead
    tink::aead::chacha20_poly1305_key
    tink::aead::chacha20_poly1305_parameters
    tink::aead::internal::testing::aead_test_vector
    tink::aead::internal::testing::chacha20_poly1305_test_vectors
)
