tink_module(daead)

add_subdirectory(subtle)
add_subdirectory(internal)

tink_cc_library(
  NAME aes_siv_key_manager
  SRCS
    aes_siv_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::deterministic_aead
    tink::core::input_stream
    tink::subtle::aes_siv_boringssl
    tink::subtle::random
    tink::util::constants
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME deterministic_aead_wrapper
  SRCS
    deterministic_aead_wrapper.cc
    deterministic_aead_wrapper.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::internal::monitoring
    tink::internal::monitoring_util
    tink::internal::registry_impl
    tink::internal::util
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME deterministic_aead_config
  SRCS
    deterministic_aead_config.cc
    deterministic_aead_config.h
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::aes_siv_proto_serialization
    tink::daead::deterministic_aead_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::tink_fips
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME deterministic_aead_factory
  SRCS
    deterministic_aead_factory.cc
    deterministic_aead_factory.h
  DEPS
    tink::daead::deterministic_aead_wrapper
    absl::core_headers
    tink::core::deterministic_aead
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::registry
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME deterministic_aead_key_templates
  SRCS
    deterministic_aead_key_templates.cc
    deterministic_aead_key_templates.h
  DEPS
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME failing_daead
  SRCS
    failing_daead.cc
    failing_daead.h
  DEPS
    absl::memory
    absl::status
    absl::strings
    tink::core::deterministic_aead
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME deterministic_aead_parameters
  SRCS
    deterministic_aead_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME deterministic_aead_key
  SRCS
    deterministic_aead_key.h
  DEPS
    tink::daead::deterministic_aead_parameters
    absl::strings
    tink::core::key
)

tink_cc_library(
  NAME aes_siv_parameters
  SRCS
    aes_siv_parameters.cc
    aes_siv_parameters.h
  DEPS
    tink::daead::deterministic_aead_parameters
    absl::status
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_siv_key
  SRCS
    aes_siv_key.cc
    aes_siv_key.h
  DEPS
    tink::daead::aes_siv_parameters
    tink::daead::deterministic_aead_key
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::internal::output_prefix_util
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_siv_proto_serialization
  SRCS
    aes_siv_proto_serialization.h
  DEPS
    tink::daead::internal::aes_siv_proto_serialization_impl
    tink::internal::mutable_serialization_registry
    tink::util::status
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::daead::internal::config_v0
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::daead::internal::key_gen_config_v0
)

# tests

tink_cc_test(
  NAME aes_siv_key_manager_test
  SRCS
    aes_siv_key_manager_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    gmock
    absl::memory
    absl::status
    tink::core::deterministic_aead
    tink::subtle::aes_siv_boringssl
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_wrapper_test
  SRCS
    deterministic_aead_wrapper_test.cc
  DEPS
    tink::daead::deterministic_aead_wrapper
    tink::daead::failing_daead
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::string_view
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::primitive_set
    tink::core::registry
    tink::internal::monitoring
    tink::internal::monitoring_client_mocks
    tink::internal::registry_impl
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_config_test
  SRCS
    deterministic_aead_config_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_key_manager
    tink::daead::aes_siv_parameters
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_key_templates
    gmock
    absl::memory
    absl::status
    absl::statusor
    tink::core::deterministic_aead
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::keyset_handle
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::registry
    tink::core::restricted_data
    tink::config::global_registry
    tink::config::tink_fips
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_siv_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_factory_test
  SRCS
    deterministic_aead_factory_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_factory
    gmock
    tink::core::key_manager_impl
    tink::core::crypto_format
    tink::core::deterministic_aead
    tink::core::keyset_handle
    tink::internal::key_info
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::aes_siv_cc_proto
)

tink_cc_test(
  NAME deterministic_aead_key_templates_test
  SRCS
    deterministic_aead_key_templates_test.cc
  DEPS
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_key_templates
    gmock
    tink::core::key_manager_impl
    tink::core::deterministic_aead
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME failing_daead_test
  SRCS
    failing_daead_test.cc
  DEPS
    tink::daead::failing_daead
    gmock
    absl::status
    tink::core::deterministic_aead
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_siv_parameters_test
  SRCS
    aes_siv_parameters_test.cc
  DEPS
    tink::daead::aes_siv_parameters
    gmock
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_siv_key_test
  SRCS
    aes_siv_key_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
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
  NAME aes_siv_proto_serialization_test
  SRCS
    aes_siv_proto_serialization_test.cc
  DEPS
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    tink::daead::aes_siv_proto_serialization
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
    tink::proto::aes_siv_cc_proto
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::daead::config_v0
    tink::daead::deterministic_aead_key_templates
    tink::daead::key_gen_config_v0
    gmock
    tink::core::deterministic_aead
    tink::core::keyset_handle
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)
