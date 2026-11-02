tink_module(prf::subtle)

tink_cc_library(
  NAME create_aes_cmac_prf
  SRCS
    create_aes_cmac_prf.cc
    create_aes_cmac_prf.h
  DEPS
    absl::status
    absl::status_macros
    absl::statusor
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::fips_utils
    tink::mac::internal::stateful_cmac_boringssl
    tink::prf::aes_cmac_prf_key
    tink::prf::aes_cmac_prf_parameters
    tink::prf::prf_set
    tink::subtle::prf::prf_set_util
  PUBLIC
)

tink_cc_test(
  NAME create_aes_cmac_prf_test
  SRCS
    create_aes_cmac_prf_test.cc
  DEPS
    tink::prf::subtle::create_aes_cmac_prf
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::internal::fips_utils
    tink::prf::prf_set
    tink::prf::internal::aes_cmac_prf_test_vectors
)

tink_cc_library(
  NAME create_hkdf_prf
  SRCS
    create_hkdf_prf.cc
    create_hkdf_prf.h
  DEPS
    absl::status
    absl::status_macros
    absl::statusor
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    tink::prf::prf_set
    tink::subtle::common_enums
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
  PUBLIC
)

tink_cc_test(
  NAME create_hkdf_prf_test
  SRCS
    create_hkdf_prf_test.cc
  DEPS
    tink::prf::subtle::create_hkdf_prf
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::fips_utils
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    tink::prf::prf_set
    tink::prf::internal::hkdf_prf_test_vectors
)
