tink_module(internal)

add_subdirectory(testing)

tink_cc_library(
  NAME ssl_util
  SRCS
    ssl_util.h
  DEPS
    crypto
)

tink_cc_library(
  NAME keyset_wrapper
  SRCS
    keyset_wrapper.h
  DEPS
    absl::flat_hash_map
    absl::statusor
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME util
  SRCS
    util.cc
    util.h
  DEPS
    absl::core_headers
    absl::absl_log
    absl::strings
)

tink_cc_library(
  NAME test_file_util
  SRCS
    test_file_util.cc
    test_file_util_cmake.cc
    test_file_util.h
  DEPS
    absl::absl_check
    absl::strings
    gmock
    tink::subtle::random
    tink::util::status
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME keyset_wrapper_impl
  SRCS
    keyset_wrapper_impl.h
  DEPS
    tink::internal::internal_insecure_secret_key_access
    tink::internal::key_info
    tink::internal::keyset_wrapper
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    absl::flat_hash_map
    absl::any_invocable
    absl::status
    absl::statusor
    absl::optional
    tink::core::key
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::restricted_data
    tink::util::validation
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME ssl_unique_ptr
  SRCS
    ssl_unique_ptr.h
  DEPS
    crypto
)

tink_cc_library(
  NAME err_util
  SRCS
    err_util.cc
    err_util.h
  DEPS
    crypto
)

tink_cc_library(
  NAME key_info
  SRCS
    key_info.cc
    key_info.h
  DEPS
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME registry_impl
  SRCS
    registry_impl.cc
    registry_impl.h
  DEPS
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_store
    tink::internal::monitoring
    absl::core_headers
    absl::flat_hash_map
    absl::any_invocable
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::synchronization
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::input_stream
    tink::core::key
    tink::core::key_manager
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME fips_utils
  SRCS
    fips_utils.cc
    fips_utils.h
  DEPS
    absl::core_headers
    absl::status
    crypto
    tink::util::status
)

tink_cc_library(
  NAME ec_util
  SRCS
    ec_util.cc
    ec_util.h
  DEPS
    tink::internal::bn_util
    tink::internal::call_with_core_dump_protection
    tink::internal::dfsan_forwarders
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::safe_stringops
    tink::internal::secret_buffer
    tink::internal::ssl_unique_ptr
    absl::config
    absl::log
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::span
    crypto
    tink::core::secret_data
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::secret_data
)

tink_cc_library(
  NAME bn_util
  SRCS
    bn_util.cc
    bn_util.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::secret_buffer
    tink::internal::ssl_unique_ptr
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME rsa_util
  SRCS
    rsa_util.cc
    rsa_util.h
  DEPS
    tink::internal::bn_util
    tink::internal::call_with_core_dump_protection
    tink::internal::err_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::ssl_util
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::secret_data
    tink::config::tink_fips
    tink::subtle::common_enums
    tink::util::errors
    tink::util::secret_data
)

tink_cc_test(
  NAME util_test
  SRCS
    util_test.cc
  DEPS
    tink::internal::util
    gmock
    absl::strings
)

tink_cc_test(
  NAME keyset_wrapper_impl_test
  SRCS
    keyset_wrapper_impl_test.cc
  DEPS
    tink::internal::key_gen_configuration_impl
    tink::internal::keyset_wrapper_impl
    tink::internal::ssl_util
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::aead
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::restricted_data
    tink::aead::aead_config
    tink::aead::aead_wrapper
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_parameters
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_test(
  NAME key_info_test
  SRCS
    key_info_test.cc
  DEPS
    tink::internal::key_info
    gmock
    protobuf::libprotobuf-lite
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME registry_impl_test
  SRCS
    registry_impl_test.cc
  DEPS
    tink::internal::fips_utils
    tink::internal::monitoring_client_mocks
    tink::internal::registry_impl
    gmock
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::aead
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::hybrid_decrypt
    tink::core::input_stream
    tink::core::key_manager
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::aead::aead_wrapper
    tink::aead::aes_gcm_key_manager
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME err_util_test
  SRCS
    err_util_test.cc
  DEPS
    tink::internal::err_util
    gmock
    absl::strings
    crypto
)

tink_cc_test(
  NAME bn_util_test
  SRCS
    bn_util_test.cc
  DEPS
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    gmock
    absl::strings
    absl::span
    crypto
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME rsa_util_test
  SRCS
    rsa_util_test.cc
  DEPS
    tink::internal::bn_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
    gmock
    absl::status
    absl::strings
    crypto
    tink::subtle::random
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME fips_utils_test
  SRCS
    fips_utils_test.cc
  DEPS
    tink::internal::fips_utils
    gmock
    absl::status
    crypto
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME ec_util_test
  SRCS
    ec_util_test.cc
  DATA
    wycheproof::testvectors
  DEPS
    tink::internal::bn_util
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::internal::ssl_unique_ptr
    tink::internal::ssl_util
    gmock
    absl::absl_check
    absl::status
    absl::strings
    absl::span
    crypto
    tink::internal::testing::wycheproof_util
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME md_util
  SRCS
    md_util.cc
    md_util.h
  DEPS
    tink::internal::err_util
    tink::internal::util
    absl::status
    absl::strings
    crypto
    tink::subtle::common_enums
    tink::subtle::subtle_util
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME md_util_test
  SRCS
    md_util_test.cc
  DEPS
    tink::internal::md_util
    gmock
    absl::strings
    crypto
    tink::subtle::common_enums
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME aes_util
  SRCS
    aes_util.cc
    aes_util.h
  DEPS
    tink::internal::util
    absl::status
    absl::strings
    absl::span
    crypto
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME aes_util_test
  SRCS
    aes_util_test.cc
  DEPS
    tink::internal::aes_util
    gmock
    absl::status
    absl::strings
    absl::span
    crypto
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME monitoring_util
  SRCS
    monitoring_util.h
  DEPS
    tink::internal::key_status_util
    tink::internal::monitoring
    absl::flat_hash_map
    absl::status
    absl::strings
    tink::core::key_status
    tink::core::primitive_set
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME monitoring_util_test
  SRCS
    monitoring_util_test.cc
  DEPS
    tink::internal::monitoring
    tink::internal::monitoring_util
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::strings
    tink::core::key_status
    tink::core::primitive_set
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME serialization
  SRCS
    serialization.h
  DEPS
    absl::strings
)

tink_cc_library(
  NAME proto_parameters_serialization
  SRCS
    proto_parameters_serialization.cc
    proto_parameters_serialization.h
  DEPS
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::internal::util
    absl::status
    absl::statusor
    absl::strings
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME proto_parameters_serialization_test
  SRCS
    proto_parameters_serialization_test.cc
  DEPS
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    gmock
    absl::status
    absl::statusor
    tink::util::test_matchers
    tink::proto::test_proto_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME proto_key_serialization
  SRCS
    proto_key_serialization.cc
    proto_key_serialization.h
  DEPS
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::internal::util
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::restricted_data
)

tink_cc_test(
  NAME proto_key_serialization_test
  SRCS
    proto_key_serialization_test.cc
  DEPS
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    gmock
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::restricted_data
    tink::util::test_matchers
)

tink_cc_library(
  NAME legacy_proto_parameters
  SRCS
    legacy_proto_parameters.cc
    legacy_proto_parameters.h
  DEPS
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    tink::core::parameters
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME legacy_proto_parameters_test
  SRCS
    legacy_proto_parameters_test.cc
  DEPS
    tink::internal::legacy_proto_parameters
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    gmock
    absl::statusor
    tink::core::parameters
    tink::util::test_matchers
    tink::proto::test_proto_cc_proto
)

tink_cc_library(
  NAME legacy_proto_key
  SRCS
    legacy_proto_key.cc
    legacy_proto_key.h
  DEPS
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME legacy_proto_key_test
  SRCS
    legacy_proto_key_test.cc
  DEPS
    tink::internal::legacy_proto_key
    tink::internal::proto_key_serialization
    tink::internal::tink_proto_structs
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::test_matchers
)

tink_cc_library(
  NAME parser_index
  SRCS
    parser_index.h
  DEPS
    tink::internal::serialization
    absl::strings
)

tink_cc_test(
  NAME parser_index_test
  SRCS
    parser_index_test.cc
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    gmock
    absl::strings
)

tink_cc_library(
  NAME serializer_index
  SRCS
    serializer_index.h
  DEPS
    tink::internal::serialization
    tink::core::key
    tink::core::parameters
)

tink_cc_test(
  NAME serializer_index_test
  SRCS
    serializer_index_test.cc
  DEPS
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
)

tink_cc_library(
  NAME parameters_parser
  SRCS
    parameters_parser.h
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    absl::status
    absl::statusor
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_parser_test
  SRCS
    parameters_parser_test.cc
  DEPS
    tink::internal::parameters_parser
    tink::internal::parser_index
    tink::internal::serialization
    tink::internal::serialization_test_util
    gmock
    absl::memory
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME parameters_serializer
  SRCS
    parameters_serializer.h
  DEPS
    tink::internal::serialization
    tink::internal::serializer_index
    absl::status
    absl::statusor
    absl::strings
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME parameters_serializer_test
  SRCS
    parameters_serializer_test.cc
  DEPS
    tink::internal::parameters_serializer
    tink::internal::serialization
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
    absl::memory
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_parser
  SRCS
    key_parser.h
  DEPS
    tink::internal::parser_index
    tink::internal::serialization
    absl::function_ref
    absl::log
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_parser_test
  SRCS
    key_parser_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::parser_index
    tink::internal::serialization
    tink::internal::serialization_test_util
    gmock
    absl::memory
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_serializer
  SRCS
    key_serializer.h
  DEPS
    tink::internal::serialization
    tink::internal::serializer_index
    absl::function_ref
    absl::log
    absl::status
    absl::statusor
    absl::optional
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_serializer_test
  SRCS
    key_serializer_test.cc
  DEPS
    tink::internal::key_serializer
    tink::internal::serialization
    tink::internal::serialization_test_util
    tink::internal::serializer_index
    gmock
    absl::memory
    absl::status
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::secret_key_access_token
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME key_status_util
  SRCS
    key_status_util.cc
    key_status_util.h
  DEPS
    absl::status
    tink::core::key_status
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME key_status_util_test
  SRCS
    key_status_util_test.cc
  DEPS
    tink::internal::key_status_util
    gmock
    absl::status
    tink::core::key_status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_handle_builder_entry
  SRCS
    keyset_handle_builder_entry.cc
    keyset_handle_builder_entry.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::key_gen_configuration_impl
    tink::internal::key_status_util
    tink::internal::key_type_info_store
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::parameters
    tink::core::registry
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::secret_proto
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_handle_builder_entry_test
  SRCS
    keyset_handle_builder_entry_test.cc
  DEPS
    tink::internal::key_gen_configuration_impl
    tink::internal::keyset_handle_builder_entry
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    gmock
    absl::memory
    absl::status
    absl::statusor
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_key_manager
    tink::aead::xchacha20_poly1305_parameters
    tink::aead::xchacha20_poly1305_proto_serialization
    tink::config::global_registry
    tink::config::tink_config
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::mac_key_templates
    tink::util::secret_proto
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME serialization_registry
  SRCS
    serialization_registry.cc
    serialization_registry.h
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::parser_index
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::serializer_index
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::str_format
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME serialization_registry_test
  SRCS
    serialization_registry_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::serialization_registry
    tink::internal::serialization_test_util
    tink::internal::tink_proto_structs
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::test_matchers
)

tink_cc_library(
  NAME mutable_serialization_registry
  SRCS
    mutable_serialization_registry.cc
    mutable_serialization_registry.h
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::serialization
    tink::internal::serialization_registry
    absl::core_headers
    absl::synchronization
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME mutable_serialization_registry_test
  SRCS
    mutable_serialization_registry_test.cc
  DEPS
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::serialization_test_util
    tink::internal::tink_proto_structs
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::util::test_matchers
)

tink_cc_library(
  NAME serialization_test_util
  SRCS
    serialization_test_util.h
  DEPS
    tink::internal::serialization
    absl::strings
    absl::optional
    tink::core::key
    tink::core::parameters
    tink::core::secret_key_access_token
    tink::util::statusor
  TESTONLY
)

tink_cc_test(
  NAME serialization_test_util_test
  SRCS
    serialization_test_util_test.cc
  DEPS
    tink::internal::serialization_test_util
    gmock
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME test_random_access_stream
  SRCS
    test_random_access_stream.cc
    test_random_access_stream.h
  DEPS
    absl::status
    absl::strings
    tink::core::random_access_stream
    tink::util::buffer
    tink::util::status
    tink::util::statusor
  TESTONLY
)

tink_cc_test(
  NAME test_random_access_stream_test
  SRCS
    test_random_access_stream_test.cc
  DEPS
    tink::internal::test_random_access_stream
    gmock
    absl::status
    tink::subtle::random
    tink::util::buffer
    tink::util::status
    tink::util::test_matchers
)

tink_cc_library(
  NAME configuration_impl
  SRCS
    configuration_impl.h
  DEPS
    tink::internal::configuration_helper
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::configuration
    tink::core::key
    tink::core::key_manager
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME configuration_impl_test
  SRCS
    configuration_impl_test.cc
  DEPS
    tink::internal::configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_store
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::core::configuration
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::registry
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_proto_serialization
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME key_type_info_store
  SRCS
    key_type_info_store.cc
    key_type_info_store.h
  DEPS
    tink::internal::fips_utils
    absl::flat_hash_map
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME key_type_info_store_test
  SRCS
    key_type_info_store_test.cc
  DEPS
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    gmock
    absl::memory
    absl::status
    absl::optional
    tink::core::aead
    tink::core::key_manager_impl
    tink::core::key_manager
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::aead::aes_gcm_key_manager
    tink::aead::cord_aead
    tink::aead::kms_envelope_aead_key_manager
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_gcm_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_wrapper_store
  SRCS
    keyset_wrapper_store.h
  DEPS
    tink::internal::configuration_helper
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_impl
    absl::flat_hash_map
    absl::any_invocable
    absl::status
    absl::statusor
    absl::strings
    tink::core::key
    tink::core::primitive_wrapper
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_wrapper_store_test
  SRCS
    keyset_wrapper_store_test.cc
  DEPS
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_store
    tink::internal::registry_impl
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key
    tink::core::mac
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::mac::mac_wrapper
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME key_gen_configuration_impl
  SRCS
    key_gen_configuration_impl.h
  DEPS
    tink::internal::key_type_info_store
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    tink::core::key
    tink::core::key_gen_configuration
    tink::core::key_manager
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME key_gen_configuration_impl_test
  SRCS
    key_gen_configuration_impl_test.cc
  DEPS
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    gmock
    absl::memory
    absl::status
    absl::string_view
    absl::optional
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key
    tink::core::key_gen_configuration
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::registry
    tink::core::restricted_data
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_parameters
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME call_with_core_dump_protection
  SRCS
    call_with_core_dump_protection.h
)

tink_cc_test(
  NAME call_with_core_dump_protection_test
  SRCS
    call_with_core_dump_protection_test.cc
  DEPS
    tink::internal::call_with_core_dump_protection
    gmock
)

tink_cc_library(
  NAME safe_stringops
  SRCS
    safe_stringops.h
  DEPS
    crypto
    tink::internal::call_with_core_dump_protection
)

tink_cc_test(
  NAME safe_stringops_test
  SRCS
    safe_stringops_test.cc
  DEPS
    tink::internal::safe_stringops
    gmock
)

tink_cc_library(
  NAME bn_encoding_util
  SRCS
    bn_encoding_util.cc
    bn_encoding_util.h
  DEPS
    tink::internal::safe_stringops
    tink::internal::secret_buffer
    absl::status
    absl::strings
    absl::str_format
    absl::string_view
    crypto
    tink::core::restricted_big_integer
    tink::core::secret_key_access_token
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME dfsan_forwarders
  SRCS
    dfsan_forwarders.h
  DEPS
    absl::base
)

tink_cc_test(
  NAME bn_encoding_util_test
  SRCS
    bn_encoding_util_test.cc
  DEPS
    tink::internal::bn_encoding_util
    gmock
    absl::status
    absl::statusor
    absl::strings
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::restricted_big_integer
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_proto(
  NAME proto_test_cc_proto
  SRCS proto_test_proto.proto
)

tink_cc_library(
  NAME proto_parsing_helpers
  SRCS
    proto_parsing_helpers.cc
    proto_parsing_helpers.h
  DEPS
    tink::internal::proto_parser_state
    absl::bits
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::span
)

tink_cc_test(
  NAME proto_parsing_helpers_test
  SRCS
    proto_parsing_helpers_test.cc
  DEPS
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    gmock
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::span
    tink::core::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_enum_field
  SRCS
    proto_parser_enum_field.h
  DEPS
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    absl::check
    absl::status
)

tink_cc_test(
  NAME proto_parser_enum_field_test
  SRCS
    proto_parser_enum_field_test.cc
  DEPS
    tink::internal::proto_parser_enum_field
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    gmock
    absl::strings
    absl::string_view
    absl::span
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_presence_fields
  SRCS
    proto_parser_presence_fields.h
  DEPS
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    absl::status
    absl::statusor
    absl::optional
)

tink_cc_test(
  NAME proto_parser_presence_fields_test
  SRCS
    proto_parser_presence_fields_test.cc
  DEPS
    tink::internal::proto_parser_presence_fields
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    gmock
    absl::strings
    absl::string_view
    absl::optional
    absl::span
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_options
  SRCS
    proto_parser_options.h
)

tink_cc_library(
  NAME proto_parser_state
  SRCS
    proto_parser_state.cc
    proto_parser_state.h
  DEPS
    tink::internal::call_with_core_dump_protection
    absl::nullability
    absl::crc32c
    absl::string_view
    absl::span
)

tink_cc_test(
  NAME proto_parser_state_test
  SRCS
    proto_parser_state_test.cc
  DEPS
    tink::internal::proto_parser_state
    gmock
    absl::crc32c
    absl::span
)

tink_cc_library(
  NAME configuration_helper
  SRCS
    configuration_helper.h
  DEPS
    absl::flat_hash_map
    absl::any_invocable
    absl::statusor
    tink::util::statusor
)

tink_cc_library(
  NAME secret_data_with_crc
  SRCS
    secret_data_with_crc.h
  DEPS
    tink::util::secret_data_internal_class
)

tink_cc_library(
  NAME output_prefix_util
  SRCS
    output_prefix_util.h
)

tink_cc_test(
  NAME output_prefix_util_test
  SRCS
    output_prefix_util_test.cc
  DEPS
    tink::internal::output_prefix_util
    gmock
)

tink_cc_library(
  NAME internal_insecure_secret_key_access
  SRCS
    internal_insecure_secret_key_access.cc
    internal_insecure_secret_key_access.h
  DEPS
    tink::core::insecure_secret_key_access
    tink::core::secret_key_access_token
)

tink_cc_library(
  NAME global_serialization_registry
  SRCS
    global_serialization_registry.cc
    global_serialization_registry.h
  DEPS
    tink::internal::serialization_registry
    absl::absl_check
    tink::aead::internal::aes_ctr_hmac_aead_proto_serialization_impl
    tink::aead::internal::aes_eax_proto_serialization_impl
    tink::aead::internal::aes_gcm_proto_serialization_impl
    tink::aead::internal::aes_gcm_siv_proto_serialization_impl
    tink::aead::internal::chacha20_poly1305_proto_serialization_impl
    tink::aead::internal::legacy_kms_aead_proto_serialization_impl
    tink::aead::internal::x_aes_gcm_proto_serialization_impl
    tink::aead::internal::xchacha20_poly1305_proto_serialization_impl
    tink::daead::internal::aes_siv_proto_serialization_impl
    tink::mac::internal::aes_cmac_proto_serialization_impl
    tink::mac::internal::hmac_proto_serialization_impl
    tink::prf::internal::aes_cmac_prf_proto_serialization_impl
    tink::prf::internal::hkdf_prf_proto_serialization_impl
    tink::prf::internal::hmac_prf_proto_serialization_impl
    tink::signature::internal::ecdsa_proto_serialization_impl
    tink::signature::internal::ed25519_proto_serialization_impl
    tink::streamingaead::internal::aes_ctr_hmac_streaming_proto_serialization_impl
    tink::streamingaead::internal::aes_gcm_hkdf_streaming_proto_serialization_impl
)

tink_cc_test(
  NAME global_serialization_registry_test
  SRCS
    global_serialization_registry_test.cc
  DEPS
    tink::internal::ec_util
    tink::internal::global_serialization_registry
    tink::internal::internal_insecure_secret_key_access
    tink::internal::proto_key_serialization
    tink::internal::serialization
    gmock
    absl::absl_check
    absl::memory
    absl::optional
    tink::core::big_integer
    tink::core::ec_point
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::aead::aes_ctr_hmac_aead_key
    tink::aead::aes_ctr_hmac_aead_parameters
    tink::aead::aes_eax_key
    tink::aead::aes_eax_parameters
    tink::aead::aes_gcm_key
    tink::aead::aes_gcm_parameters
    tink::aead::aes_gcm_siv_key
    tink::aead::aes_gcm_siv_parameters
    tink::aead::chacha20_poly1305_key
    tink::aead::chacha20_poly1305_parameters
    tink::aead::legacy_kms_aead_key
    tink::aead::legacy_kms_aead_parameters
    tink::aead::x_aes_gcm_key
    tink::aead::x_aes_gcm_parameters
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_parameters
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::hmac_key
    tink::mac::hmac_parameters
    tink::prf::aes_cmac_prf_key
    tink::prf::hkdf_prf_key
    tink::prf::hkdf_prf_parameters
    tink::prf::hmac_prf_key
    tink::prf::hmac_prf_parameters
    tink::signature::ecdsa_parameters
    tink::signature::ecdsa_private_key
    tink::signature::ecdsa_public_key
    tink::signature::ed25519_parameters
    tink::signature::ed25519_private_key
    tink::signature::ed25519_public_key
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    tink::streamingaead::aes_gcm_hkdf_streaming_key
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::secret_data
    tink::util::test_matchers
)

tink_cc_library(
  NAME sanitizing_allocator
  SRCS
    sanitizing_allocator.h
  DEPS
    absl::config
    absl::core_headers
    crypto
)

tink_cc_test(
  NAME sanitizing_allocator_test
  SRCS
    sanitizing_allocator_test.cc
  DEPS
    tink::internal::sanitizing_allocator
    gmock
)

tink_cc_library(
  NAME secret_buffer
  SRCS
    secret_buffer.h
  DEPS
    tink::internal::safe_stringops
    tink::internal::sanitizing_allocator
    absl::absl_check
    absl::check
    absl::string_view
    absl::span
)

tink_cc_test(
  NAME secret_buffer_test
  SRCS
    secret_buffer_test.cc
  DEPS
    tink::internal::secret_buffer
    gmock
    absl::string_view
    absl::span
    tink::util::secret_data
    tink::util::test_util
)

tink_cc_library(
  NAME tink_proto_structs
  SRCS
    tink_proto_structs.cc
    tink_proto_structs.h
  DEPS
    tink::internal::proto_parser_enum_field
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_message
    tink::internal::proto_parser_secret_data_field
    absl::no_destructor
    absl::string_view
    tink::core::secret_data
    tink::util::secret_data
)

tink_cc_test(
  NAME tink_proto_structs_test
  SRCS
    tink_proto_structs_test.cc
  DEPS
    tink::internal::tink_proto_structs
    gmock
    absl::statusor
    absl::strings
    tink::core::secret_data
    tink::internal::testing::field_with_number
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME common_proto_enums
  SRCS
    common_proto_enums.h
)

tink_cc_library(
  NAME proto_parser_repeated_secret_data_field
  SRCS
    proto_parser_repeated_secret_data_field.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    tink::internal::safe_stringops
    absl::crc32c
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::secret_data
    tink::util::secret_data
)

tink_cc_test(
  NAME proto_parser_repeated_secret_data_field_test
  SRCS
    proto_parser_repeated_secret_data_field_test.cc
  DEPS
    tink::internal::proto_parser_repeated_secret_data_field
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    gmock
    absl::crc32c
    absl::strings
    absl::string_view
    absl::span
    tink::core::secret_data
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME monitoring
  SRCS
    monitoring.h
  DEPS
    tink::internal::monitoring_context
    absl::statusor
)

tink_cc_library(
  NAME monitoring_client_mocks
  SRCS
    monitoring_client_mocks.h
  DEPS
    tink::internal::monitoring
    gmock
    tink::util::statusor
  TESTONLY
)

tink_cc_library(
  NAME endian
  SRCS
    endian.h
)

tink_cc_test(
  NAME endian_test
  SRCS
    endian_test.cc
  DEPS
    tink::internal::endian
    gmock
)

tink_cc_library(
  NAME monitoring_context
  SRCS
    monitoring_context.h
  DEPS
    tink::internal::monitoring_key_set_info
    absl::string_view
)

tink_cc_library(
  NAME monitoring_key_set_info
  SRCS
    monitoring_key_set_info.h
  DEPS
    tink::internal::key_status_util
    absl::flat_hash_map
    absl::string_view
    tink::core::key_status
)

tink_cc_test(
  NAME monitoring_key_set_info_test
  SRCS
    monitoring_key_set_info_test.cc
  DEPS
    tink::internal::monitoring_key_set_info
    gmock
    tink::core::key_status
)

tink_cc_library(
  NAME xwing_util
  SRCS
    xwing_util.cc
    xwing_util.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::secret_buffer
    absl::log
    absl::status
    absl::statusor
    crypto
    tink::core::secret_data
    tink::util::secret_data
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME xwing_util_test
  SRCS
    xwing_util_test.cc
  DEPS
    tink::internal::xwing_util
    gmock
    absl::statusor
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME mlkem_util
  SRCS
    mlkem_util.cc
    mlkem_util.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::secret_buffer
    absl::memory
    absl::status
    absl::statusor
    crypto
    tink::core::secret_data
    tink::subtle::subtle_util
    tink::util::secret_data
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME mlkem_util_test
  SRCS
    mlkem_util_test.cc
  DEPS
    tink::internal::mlkem_util
    gmock
    absl::status
    absl::statusor
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME proto_parser_fields
  SRCS
    proto_parser_fields.h
  DEPS
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    tink::internal::proto_parser_string_like_helpers
    tink::internal::proto_parsing_helpers
    absl::core_headers
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::secret_data
)

tink_cc_test(
  NAME proto_parser_fields_test
  SRCS
    proto_parser_fields_test.cc
  DEPS
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    gmock
    absl::strings
    absl::string_view
    absl::span
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_message
  SRCS
    proto_parser_message.h
  DEPS
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    tink::internal::secret_buffer
    absl::algorithm_container
    absl::no_destructor
    absl::nullability
    absl::crc32c
    absl::absl_check
    absl::check
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    absl::span
    tink::core::secret_data
    tink::subtle::subtle_util
    tink::util::secret_data
)

tink_cc_test(
  NAME proto_parser_message_test
  SRCS
    proto_parser_message_test.cc
  DEPS
    tink::internal::proto_parser_enum_field
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_message
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    gmock
    absl::nullability
    absl::crc32c
    absl::absl_check
    absl::status
    absl::strings
    absl::string_view
    absl::span
    tink::core::secret_data
    tink::internal::testing::field_with_number
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_secret_data_field
  SRCS
    proto_parser_secret_data_field.h
  DEPS
    tink::internal::call_with_core_dump_protection
    tink::internal::proto_parser_fields
    tink::internal::proto_parser_options
    tink::internal::proto_parser_state
    tink::internal::proto_parsing_helpers
    tink::internal::safe_stringops
    absl::crc32c
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::secret_data
    tink::util::secret_data
)

tink_cc_test(
  NAME proto_parser_secret_data_field_test
  SRCS
    proto_parser_secret_data_field_test.cc
  DEPS
    tink::internal::proto_parser_options
    tink::internal::proto_parser_secret_data_field
    tink::internal::proto_parser_state
    gmock
    absl::crc32c
    absl::strings
    absl::string_view
    absl::span
    tink::core::secret_data
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_library(
  NAME proto_parser_string_like_helpers
  SRCS
    proto_parser_string_like_helpers.h
  DEPS
    absl::string_view
    absl::span
)

tink_cc_test(
  NAME proto_parser_string_like_helpers_test
  SRCS
    proto_parser_string_like_helpers_test.cc
  DEPS
    tink::internal::proto_parser_string_like_helpers
    gmock
    absl::string_view
    absl::span
)
