tink_module(hybrid::subtle)

tink_cc_library(
  NAME create_ecies_key
  SRCS
    create_ecies_key.cc
    create_ecies_key.h
  DEPS
    absl::statusor
    tink::hybrid::ecies_parameters
    tink::hybrid::ecies_private_key
    tink::hybrid::internal::ecies_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_ecies_key_test
  SRCS
    create_ecies_key_test.cc
  DEPS
    tink::hybrid::subtle::create_ecies_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::hybrid::ecies_parameters
    tink::hybrid::ecies_private_key
)

tink_cc_library(
  NAME create_hpke_key
  SRCS
    create_hpke_key.cc
    create_hpke_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::internal::hpke_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_hpke_key_test
  SRCS
    create_hpke_key_test.cc
  DEPS
    tink::hybrid::subtle::create_hpke_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
)

tink_cc_library(
  NAME create_hpke_decrypt
  SRCS
    create_hpke_decrypt.cc
    create_hpke_decrypt.h
  DEPS
    absl::statusor
    tink::core::hybrid_decrypt
    tink::hybrid::hpke_private_key
    tink::hybrid::internal::hpke_decrypt
  PUBLIC
)

tink_cc_test(
  NAME create_hpke_decrypt_test
  SRCS
    create_hpke_decrypt_test.cc
  DEPS
    tink::hybrid::subtle::create_hpke_decrypt
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::hybrid_decrypt
    tink::core::partial_key_access
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    tink::hybrid::internal::testing::hpke_test_vectors
    tink::hybrid::internal::testing::hybrid_test_vectors
    tink::internal::testing::ec_test_vectors
    tink::subtle::common_enums
)
