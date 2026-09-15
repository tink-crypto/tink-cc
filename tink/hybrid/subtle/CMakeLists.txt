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
