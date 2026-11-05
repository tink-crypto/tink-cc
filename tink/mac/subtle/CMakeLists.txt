tink_module(mac::subtle)

tink_cc_library(
  NAME create_hmac_mac
  SRCS
    create_hmac_mac.cc
    create_hmac_mac.h
  DEPS
    absl::statusor
    tink::core::mac
    tink::mac::hmac_key
    tink::mac::internal::hmac_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_hmac_mac_test
  SRCS
    create_hmac_mac_test.cc
  DEPS
    tink::mac::subtle::create_hmac_mac
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::mac
    tink::internal::fips_utils
    tink::mac::internal::hmac_test_vectors
)

tink_cc_library(
  NAME create_aes_cmac_mac
  SRCS
    create_aes_cmac_mac.cc
    create_aes_cmac_mac.h
  DEPS
    absl::statusor
    tink::core::mac
    tink::mac::aes_cmac_key
    tink::mac::internal::aes_cmac_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_aes_cmac_mac_test
  SRCS
    create_aes_cmac_mac_test.cc
  DEPS
    tink::mac::subtle::create_aes_cmac_mac
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::mac
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::fips_utils
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::internal::aes_cmac_test_vectors
)

tink_cc_library(
  NAME create_aes_cmac_chunked_mac
  SRCS
    create_aes_cmac_chunked_mac.cc
    create_aes_cmac_chunked_mac.h
  DEPS
    absl::statusor
    tink::core::chunked_mac
    tink::mac::aes_cmac_key
    tink::mac::internal::chunked_mac_impl
  PUBLIC
)

tink_cc_test(
  NAME create_aes_cmac_chunked_mac_test
  SRCS
    create_aes_cmac_chunked_mac_test.cc
  DEPS
    tink::mac::subtle::create_aes_cmac_chunked_mac
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::chunked_mac
    tink::internal::fips_utils
    tink::mac::internal::aes_cmac_test_vectors
)

tink_cc_library(
  NAME create_hmac_chunked_mac
  SRCS
    create_hmac_chunked_mac.cc
    create_hmac_chunked_mac.h
  DEPS
    absl::statusor
    tink::core::chunked_mac
    tink::mac::hmac_key
    tink::mac::internal::chunked_mac_impl
  PUBLIC
)

tink_cc_test(
  NAME create_hmac_chunked_mac_test
  SRCS
    create_hmac_chunked_mac_test.cc
  DEPS
    tink::mac::subtle::create_hmac_chunked_mac
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::chunked_mac
    tink::internal::fips_utils
    tink::mac::hmac_parameters
    tink::mac::internal::hmac_test_vectors
)
