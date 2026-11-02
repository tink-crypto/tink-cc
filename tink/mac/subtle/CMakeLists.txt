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
