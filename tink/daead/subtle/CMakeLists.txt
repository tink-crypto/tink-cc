tink_module(daead::subtle)

tink_cc_library(
  NAME aead_or_daead
  SRCS
    aead_or_daead.cc
    aead_or_daead.h
  DEPS
    absl::bind_front
    absl::string_view
    absl::variant
    tink::core::aead
    tink::core::deterministic_aead
    tink::util::statusor
)

tink_cc_test(
  NAME aead_or_daead_test
  SRCS
    aead_or_daead_test.cc
  DEPS
    tink::daead::subtle::aead_or_daead
    gmock
    absl::memory
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::aead
    tink::core::deterministic_aead
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME create_aes_siv_deterministic_aead
  SRCS
    create_aes_siv_deterministic_aead.cc
    create_aes_siv_deterministic_aead.h
  DEPS
    absl::statusor
    tink::core::deterministic_aead
    tink::daead::aes_siv_key
    tink::daead::internal::aes_siv_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_aes_siv_deterministic_aead_test
  SRCS
    create_aes_siv_deterministic_aead_test.cc
  DEPS
    tink::daead::subtle::create_aes_siv_deterministic_aead
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::deterministic_aead
    tink::daead::aes_siv_parameters
    tink::daead::internal::aes_siv_test_vectors
)
