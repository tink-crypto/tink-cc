tink_module(prf)

add_subdirectory(internal)

tink_cc_library(
  NAME hkdf_prf_key_manager
  SRCS
    hkdf_prf_key_manager.h
  DEPS
    tink::prf::prf_set
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::subtle::subtle
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
    tink::util::constants
    tink::util::enums
    tink::util::input_stream_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME prf_config
  SRCS
    prf_config.cc
    prf_config.h
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::aes_cmac_prf_proto_serialization
    tink::prf::hkdf_prf_key_manager
    tink::prf::hkdf_prf_proto_serialization
    tink::prf::hmac_prf_key_manager
    tink::prf::hmac_prf_proto_serialization
    tink::prf::prf_set_wrapper
    absl::memory
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME prf_key_templates
  SRCS
    prf_key_templates.cc
    prf_key_templates.h
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    absl::memory
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME prf_set
  SRCS
    prf_set.cc
    prf_set.h
  DEPS
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME prf_set_wrapper
  SRCS
    prf_set_wrapper.cc
    prf_set_wrapper.h
  DEPS
    tink::prf::prf_set
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::monitoring_util
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aes_cmac_prf_key_manager
  SRCS
    aes_cmac_prf_key_manager.h
  DEPS
    tink::prf::prf_set
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    tink::mac::internal::stateful_cmac_boringssl
    tink::subtle::random
    tink::subtle::prf::prf_set_util
    tink::util::constants
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME hmac_prf_key_manager
  SRCS
    hmac_prf_key_manager.cc
    hmac_prf_key_manager.h
  DEPS
    tink::prf::prf_set
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    tink::internal::fips_utils
    tink::mac::internal::stateful_hmac_boringssl
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::prf::prf_set_util
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME failing_prfset
  SRCS
    failing_prfset.cc
    failing_prfset.h
  DEPS
    tink::prf::prf_set
    absl::memory
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::prf::internal::config_v0
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::prf::internal::key_gen_config_v0
)

tink_cc_library(
  NAME prf_key
  SRCS
    prf_key.h
  DEPS
    tink::prf::prf_parameters
    absl::optional
    tink::core::key
)

tink_cc_library(
  NAME prf_parameters
  SRCS
    prf_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME aes_cmac_prf_parameters
  SRCS
    aes_cmac_prf_parameters.cc
    aes_cmac_prf_parameters.h
  DEPS
    tink::prf::prf_parameters
    absl::status
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_prf_key
  SRCS
    aes_cmac_prf_key.cc
    aes_cmac_prf_key.h
  DEPS
    tink::prf::aes_cmac_prf_parameters
    tink::prf::prf_key
    absl::statusor
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::statusor
)

tink_cc_library(
  NAME aes_cmac_prf_proto_serialization
  SRCS
    aes_cmac_prf_proto_serialization.h
  DEPS
    tink::internal::mutable_serialization_registry
    tink::prf::internal::aes_cmac_prf_proto_serialization_impl
    tink::util::status
)

tink_cc_library(
  NAME hmac_prf_parameters
  SRCS
    hmac_prf_parameters.cc
    hmac_prf_parameters.h
  DEPS
    tink::prf::prf_parameters
    absl::status
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hmac_prf_key
  SRCS
    hmac_prf_key.cc
    hmac_prf_key.h
  DEPS
    tink::prf::hmac_prf_parameters
    tink::prf::prf_key
    absl::status
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hmac_prf_proto_serialization
  SRCS
    hmac_prf_proto_serialization.h
  DEPS
    tink::internal::mutable_serialization_registry
    tink::prf::internal::hmac_prf_proto_serialization_impl
    tink::util::status
)

tink_cc_library(
  NAME hkdf_prf_parameters
  SRCS
    hkdf_prf_parameters.cc
    hkdf_prf_parameters.h
  DEPS
    tink::prf::prf_parameters
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hkdf_prf_key
  SRCS
    hkdf_prf_key.cc
    hkdf_prf_key.h
  DEPS
    tink::prf::hkdf_prf_parameters
    tink::prf::prf_key
    absl::status
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hkdf_prf_proto_serialization
  SRCS
    hkdf_prf_proto_serialization.h
  DEPS
    tink::internal::mutable_serialization_registry
    tink::prf::internal::hkdf_prf_proto_serialization_impl
    tink::util::status
)

# tests

tink_cc_test(
  NAME hkdf_prf_key_manager_test
  SRCS
    hkdf_prf_key_manager_test.cc
  DEPS
    tink::prf::hkdf_prf_key_manager
    tink::prf::prf_set
    gmock
    absl::memory
    absl::status
    tink::core::input_stream
    tink::subtle::subtle
    tink::subtle::prf::hkdf_streaming_prf
    tink::subtle::prf::prf_set_util
    tink::subtle::prf::streaming_prf
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_key_templates_test
  SRCS
    prf_key_templates_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_key_templates
    gmock
    absl::memory
    tink::util::test_matchers
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::hkdf_prf_cc_proto
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_set_wrapper_test
  SRCS
    prf_set_wrapper_test.cc
  DEPS
    tink::prf::prf_set
    tink::prf::prf_set_wrapper
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    tink::core::primitive_set
    tink::core::registry
    tink::internal::registry_impl
    tink::monitoring::monitoring
    tink::monitoring::monitoring_client_mocks
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_set_test
  SRCS
    prf_set_test.cc
  DEPS
    tink::prf::prf_config
    tink::prf::prf_key_templates
    tink::prf::prf_set
    gmock
    absl::memory
    absl::strings
    tink::core::keyset_handle
    tink::core::keyset_manager
    tink::config::global_registry
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME aes_cmac_prf_key_manager_test
  SRCS
    aes_cmac_prf_key_manager_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::prf_set
    gmock
    absl::memory
    tink::core::input_stream
    tink::subtle::aes_cmac_boringssl
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME hmac_prf_key_manager_test
  SRCS
    hmac_prf_key_manager_test.cc
  DEPS
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set
    gmock
    absl::memory
    absl::status
    absl::statusor
    tink::core::key_manager_impl
    tink::subtle::hmac_boringssl
    tink::util::enums
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::hmac_prf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME prf_config_test
  SRCS
    prf_config_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key
    tink::prf::aes_cmac_prf_parameters
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    tink::prf::hmac_prf_key
    tink::prf::hmac_prf_key_manager
    tink::prf::hmac_prf_parameters
    tink::prf::key_gen_config_v0
    tink::prf::prf_config
    tink::prf::prf_key_templates
    tink::prf::prf_set
    gmock
    absl::status
    absl::optional
    crypto
    tink::core::insecure_secret_key_access_testonly
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::registry
    tink::core::restricted_data
    tink::config::global_registry
    tink::internal::fips_utils
    tink::internal::legacy_proto_key
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::subtle::random
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME failing_prfset_test
  SRCS
    failing_prfset_test.cc
  DEPS
    tink::prf::failing_prfset
    tink::prf::prf_set
    gmock
    absl::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::prf::config_v0
    tink::prf::key_gen_config_v0
    tink::prf::prf_key_templates
    tink::prf::prf_set
    gmock
    tink::core::keyset_handle
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_cmac_prf_parameters_test
  SRCS
    aes_cmac_prf_parameters_test.cc
  DEPS
    tink::prf::aes_cmac_prf_parameters
    gmock
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_cmac_prf_key_test
  SRCS
    aes_cmac_prf_key_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key
    tink::prf::aes_cmac_prf_parameters
    gmock
    absl::status
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_cmac_prf_proto_serialization_test
  SRCS
    aes_cmac_prf_proto_serialization_test.cc
  DEPS
    tink::prf::aes_cmac_prf_key
    tink::prf::aes_cmac_prf_parameters
    tink::prf::aes_cmac_prf_proto_serialization
    gmock
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access_testonly
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::proto::aes_cmac_prf_cc_proto
)

tink_cc_test(
  NAME hmac_prf_parameters_test
  SRCS
    hmac_prf_parameters_test.cc
  DEPS
    tink::prf::hmac_prf_parameters
    gmock
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hmac_prf_key_test
  SRCS
    hmac_prf_key_test.cc
  DEPS
    tink::prf::hmac_prf_key
    tink::prf::hmac_prf_parameters
    gmock
    absl::status
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME hmac_prf_proto_serialization_test
  SRCS
    hmac_prf_proto_serialization_test.cc
  DEPS
    tink::prf::hmac_prf_key
    tink::prf::hmac_prf_parameters
    tink::prf::hmac_prf_proto_serialization
    gmock
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::hmac_prf_cc_proto
)

tink_cc_test(
  NAME hkdf_prf_parameters_test
  SRCS
    hkdf_prf_parameters_test.cc
  DEPS
    tink::prf::hkdf_prf_parameters
    gmock
    absl::status
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hkdf_prf_key_test
  SRCS
    hkdf_prf_key_test.cc
  DEPS
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    gmock
    absl::status
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME hkdf_prf_proto_serialization_test
  SRCS
    hkdf_prf_proto_serialization_test.cc
  DEPS
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    tink::prf::hkdf_prf_proto_serialization
    gmock
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::hkdf_prf_cc_proto
)
