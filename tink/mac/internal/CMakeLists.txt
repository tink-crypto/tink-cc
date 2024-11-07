tink_module(mac::internal)

tink_cc_library(
  NAME chunked_mac_impl
  SRCS
    chunked_mac_impl.cc
    chunked_mac_impl.h
  DEPS
    tink::mac::internal::stateful_cmac_boringssl
    tink::mac::internal::stateful_hmac_boringssl
    tink::mac::internal::stateful_mac
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::chunked_mac
    tink::internal::safe_stringops
    tink::subtle::common_enums
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::aes_cmac_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_library(
  NAME chunked_mac_wrapper
  SRCS
    chunked_mac_wrapper.cc
    chunked_mac_wrapper.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::chunked_mac
    tink::core::crypto_format
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    tink::mac::internal::chunked_mac_wrapper
    absl::memory
    tink::core::configuration
    tink::internal::configuration_impl
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_wrapper
    tink::util::status
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::internal::key_gen_configuration_impl
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::util::status
)

tink_cc_library(
  NAME stateful_hmac_boringssl
  SRCS
    stateful_hmac_boringssl.cc
    stateful_hmac_boringssl.h
  DEPS
    tink::mac::internal::stateful_mac
    absl::memory
    absl::status
    absl::string_view
    crypto
    tink::internal::md_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME stateful_cmac_boringssl
  SRCS
    stateful_cmac_boringssl.cc
    stateful_cmac_boringssl.h
  DEPS
    tink::mac::internal::stateful_mac
    absl::memory
    absl::status
    absl::string_view
    crypto
    tink::internal::aes_util
    tink::internal::ssl_unique_ptr
    tink::internal::util
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME stateful_mac
  SRCS
    stateful_mac.h
  DEPS
    absl::core_headers
    absl::string_view
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

# tests

tink_cc_test(
  NAME chunked_mac_impl_test
  SRCS
    chunked_mac_impl_test.cc
  DEPS
    tink::mac::internal::chunked_mac_impl
    tink::mac::internal::stateful_mac
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::core::chunked_mac
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_test(
  NAME chunked_mac_wrapper_test
  SRCS
    chunked_mac_wrapper_test.cc
  DEPS
    tink::mac::internal::chunked_mac_impl
    tink::mac::internal::chunked_mac_wrapper
    tink::mac::internal::stateful_mac
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::chunked_mac
    tink::core::primitive_set
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME chunked_mac_test
  SRCS
    chunked_mac_test.cc
  DEPS
    gmock
    absl::status
    tink::core::chunked_mac
    tink::core::keyset_handle
    tink::core::mac
    tink::config::global_registry
    tink::mac::mac_config
    tink::mac::mac_key_templates
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::mac::internal::config_v0
    tink::mac::internal::key_gen_config_v0
    gmock
    tink::core::chunked_mac
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::core::mac
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::mac::mac_key_templates
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME stateful_hmac_boringssl_test
  SRCS
    stateful_hmac_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::mac::internal::stateful_hmac_boringssl
    tink::mac::internal::stateful_mac
    gmock
    absl::log
    absl::check
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    rapidjson
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::wycheproof_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME stateful_cmac_boringssl_test
  SRCS
    stateful_cmac_boringssl_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::mac::internal::stateful_cmac_boringssl
    tink::mac::internal::stateful_mac
    gmock
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    rapidjson
    tink::subtle::common_enums
    tink::subtle::wycheproof_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)
