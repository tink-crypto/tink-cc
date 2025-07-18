add_subdirectory(aead)
add_subdirectory(config)
add_subdirectory(daead)
add_subdirectory(hybrid)
add_subdirectory(internal)
add_subdirectory(mac)
add_subdirectory(json)
add_subdirectory(jwt)
add_subdirectory(keyderivation)
add_subdirectory(prf)
add_subdirectory(signature)
add_subdirectory(streamingaead)
add_subdirectory(subtle)
add_subdirectory(util)

tink_module(core)

# Configuration settings for the build.

if(USE_ONLY_FIPS)
    target_compile_definitions(tink_internal_fips_utils PUBLIC TINK_USE_ONLY_FIPS)
endif()

# Public libraries.

set(TINK_VERSION_H "${TINK_GENFILE_DIR}/tink/version.h")

tink_cc_library(
  NAME cc
  SRCS
    aead.h
    aead_config.h
    aead_factory.h
    aead_key_templates.h
    binary_keyset_reader.h
    binary_keyset_writer.h
    cleartext_keyset_handle.h
    deterministic_aead.h
    deterministic_aead_config.h
    deterministic_aead_factory.h
    deterministic_aead_key_templates.h
    hybrid_config.h
    hybrid_decrypt.h
    hybrid_decrypt_factory.h
    hybrid_encrypt.h
    hybrid_encrypt_factory.h
    hybrid_key_templates.h
    input_stream.h
    json_keyset_reader.h
    json_keyset_writer.h
    key_manager.h
    keyset_handle.h
    keyset_manager.h
    keyset_reader.h
    keyset_writer.h
    kms_client.h
    mac.h
    mac_config.h
    mac_factory.h
    mac_key_templates.h
    output_stream.h
    output_stream_with_result.h
    public_key_sign.h
    public_key_sign_factory.h
    public_key_verify.h
    public_key_verify_factory.h
    random_access_stream.h
    registry.h
    signature_config.h
    signature_key_templates.h
    streaming_aead.h
    streaming_aead_config.h
    streaming_aead_key_templates.h
    streaming_mac.h
    tink_config.h
    "${TINK_VERSION_H}"
  DEPS
    tink::core::aead
    tink::core::binary_keyset_reader
    tink::core::binary_keyset_writer
    tink::core::cleartext_keyset_handle
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::input_stream
    tink::core::json_keyset_reader
    tink::core::json_keyset_writer
    tink::core::key
    tink::core::key_manager
    tink::core::keyset_handle
    tink::core::keyset_manager
    tink::core::keyset_reader
    tink::core::keyset_writer
    tink::core::kms_client
    tink::core::mac
    tink::core::output_stream
    tink::core::output_stream_with_result
    tink::core::parameters
    tink::core::primitive_set
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::random_access_stream
    tink::core::registry
    tink::core::streaming_aead
    tink::core::streaming_mac
    tink::core::version
    absl::core_headers
    absl::flat_hash_map
    absl::memory
    absl::optional
    absl::status
    absl::strings
    absl::synchronization
    tink::aead::aead_config
    tink::aead::aead_factory
    tink::aead::aead_key_templates
    tink::config::tink_config
    tink::daead::deterministic_aead_config
    tink::daead::deterministic_aead_factory
    tink::daead::deterministic_aead_key_templates
    tink::hybrid::hybrid_config
    tink::hybrid::hybrid_decrypt_factory
    tink::hybrid::hybrid_encrypt_factory
    tink::hybrid::hybrid_key_templates
    tink::internal::key_info
    tink::internal::keyset_handle_builder_entry
    tink::internal::registry_impl
    tink::mac::mac_config
    tink::mac::mac_factory
    tink::mac::mac_key_templates
    tink::signature::public_key_sign_factory
    tink::signature::public_key_verify_factory
    tink::signature::signature_config
    tink::signature::signature_key_templates
    tink::streamingaead::streaming_aead_config
    tink::streamingaead::streaming_aead_key_templates
    tink::util::buffer
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::config_cc_proto
    tink::proto::tink_cc_proto
  PUBLIC
)

add_library(tink::static ALIAS tink_core_cc)

tink_cc_library(
  NAME input_stream
  SRCS
    input_stream.h
  DEPS
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME output_stream
  SRCS
    output_stream.h
  DEPS
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME random_access_stream
  SRCS
    random_access_stream.h
  DEPS
    tink::util::buffer
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME output_stream_with_result
  SRCS
    output_stream_with_result.h
  DEPS
    tink::core::output_stream
    absl::status
    absl::statusor
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aead
  SRCS
    aead.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME deterministic_aead
  SRCS
    deterministic_aead.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_aead
  SRCS
    streaming_aead.h
  DEPS
    tink::core::input_stream
    tink::core::output_stream
    tink::core::random_access_stream
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME streaming_mac
  SRCS
    streaming_mac.h
  DEPS
    tink::core::output_stream_with_result
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME chunked_mac
  SRCS
    chunked_mac.h
  DEPS
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME hybrid_decrypt
  SRCS
    hybrid_decrypt.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME hybrid_encrypt
  SRCS
    hybrid_encrypt.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME mac
  SRCS
    mac.h
  DEPS
    absl::strings
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME public_key_sign
  SRCS
    public_key_sign.h
  DEPS
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME public_key_verify
  SRCS
    public_key_verify.h
  DEPS
    absl::strings
    tink::util::status
)

tink_cc_library(
  NAME keyset_reader
  SRCS
    keyset_reader.h
  DEPS
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_writer
  SRCS
    keyset_writer.h
  DEPS
    absl::status
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME binary_keyset_reader
  SRCS
    core/binary_keyset_reader.cc
    binary_keyset_reader.h
  DEPS
    tink::core::keyset_reader
    absl::memory
    absl::status
    absl::strings
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME binary_keyset_writer
  SRCS
    core/binary_keyset_writer.cc
    binary_keyset_writer.h
  DEPS
    tink::core::keyset_writer
    absl::memory
    absl::status
    absl::strings
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME json_keyset_reader
  SRCS
    json_keyset_reader.h
  DEPS
    tink::json::json_keyset_reader
)

tink_cc_library(
  NAME json_keyset_writer
  SRCS
    json_keyset_writer.h
  DEPS
    tink::json::json_keyset_writer
)

tink_cc_library(
  NAME crypto_format
  SRCS
    core/crypto_format.cc
    crypto_format.h
  DEPS
    absl::status
    absl::statusor
    absl::string_view
    tink::internal::endian
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME primitive_set
  SRCS
    primitive_set.h
    primitive_set.h
  DEPS
    tink::core::crypto_format
    absl::core_headers
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    absl::synchronization
    tink::util::errors
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME primitive_wrapper
  SRCS
    primitive_wrapper.h
  DEPS
    tink::core::primitive_set
    absl::statusor
    tink::util::statusor
)

tink_cc_library(
  NAME registry
  SRCS
    registry.h
  DEPS
    tink::core::key_manager
    tink::core::primitive_set
    absl::status
    absl::statusor
    absl::strings
    tink::internal::registry_impl
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

# Generate TINK_VERSION_H from version.h.templ. TINK_VERSION_LABEL is
# substituted in version.h.templ with the value of PROJECT_VERSION.
set(TINK_VERSION_LABEL "${PROJECT_VERSION}")
configure_file(version.h.templ "${TINK_VERSION_H}")

tink_cc_library(
  NAME version
  SRCS
    core/version.cc
    "${TINK_VERSION_H}"
)

tink_cc_library(
  NAME keyset_handle
  SRCS
    core/keyset_handle.cc
    core/keyset_handle_builder.cc
    keyset_handle.h
    keyset_handle_builder.h
  DEPS
    tink::core::aead
    tink::core::configuration
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::key_gen_configuration
    tink::core::key_manager
    tink::core::key_status
    tink::core::keyset_reader
    tink::core::keyset_writer
    tink::core::parameters
    tink::core::primitive_set
    tink::core::private_key
    tink::core::registry
    tink::core::restricted_data
    tink::core::secret_key_access_token
    absl::core_headers
    absl::flat_hash_map
    absl::check
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::optional
    tink::config::global_registry
    tink::internal::call_with_core_dump_protection
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_info
    tink::internal::key_status_util
    tink::internal::key_type_info_store
    tink::internal::keyset_handle_builder_entry
    tink::internal::keyset_wrapper
    tink::internal::keyset_wrapper_store
    tink::internal::legacy_proto_key
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::registry_impl
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::internal::util
    tink::subtle::random
    tink::util::errors
    tink::util::keyset_util
    tink::util::secret_data
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::tink_cc_proto
)

add_library(tink::core::keyset_handle_builder ALIAS tink_internal_core_keyset_handle)

tink_cc_library(
  NAME cleartext_keyset_handle
  SRCS
    core/cleartext_keyset_handle.cc
    cleartext_keyset_handle.h
  DEPS
    tink::core::keyset_handle
    tink::core::keyset_reader
    tink::core::keyset_writer
    absl::flat_hash_map
    absl::memory
    absl::status
    tink::util::errors
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME key_manager
  SRCS
    core/key_manager.cc
    key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME keyset_manager
  SRCS
    core/keyset_manager.cc
    keyset_manager.h
  DEPS
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    absl::core_headers
    absl::memory
    absl::status
    absl::statusor
    absl::synchronization
    tink::internal::key_gen_configuration_impl
    tink::util::enums
    tink::util::errors
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
  PUBLIC
)

tink_cc_library(
  NAME kms_client
  SRCS
    kms_client.h
  DEPS
    tink::core::aead
    absl::strings
    tink::util::statusor
)

tink_cc_library(
  NAME kms_clients
  SRCS
    core/kms_clients.cc
    kms_clients.h
  DEPS
    tink::core::kms_client
    absl::core_headers
    absl::status
    absl::statusor
    absl::strings
    absl::synchronization
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME template_util
  SRCS
    core/template_util.h
  DEPS
    absl::type_traits
)

tink_cc_library(
  NAME key_type_manager
  SRCS
    core/key_type_manager.h
  DEPS
    tink::core::template_util
    tink::core::input_stream
    absl::status
    absl::statusor
    absl::strings
    tink::internal::fips_utils
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME key_manager_impl
  SRCS
    core/key_manager_impl.h
  DEPS
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    absl::base
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::internal::call_with_core_dump_protection
    tink::util::constants
    tink::util::errors
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME private_key_type_manager
  SRCS
    core/private_key_type_manager.h
  DEPS
    tink::core::key_type_manager
    tink::core::template_util
    absl::statusor
    tink::util::statusor
)

tink_cc_library(
  NAME private_key_manager_impl
  SRCS
    core/private_key_manager_impl.h
  DEPS
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::key_manager
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::internal::call_with_core_dump_protection
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::util::validation
)

tink_cc_library(
  NAME key_access
  SRCS
    key_access.h
)

tink_cc_library(
  NAME secret_key_access
  SRCS
    secret_key_access.h
  DEPS
    tink::core::key_access
)

add_library(tink::core::secret_key_access_testonly ALIAS tink_internal_core_secret_key_access)

add_library(tink::core::cleartext_keyset_handle_testonly ALIAS tink_internal_core_cleartext_keyset_handle)

tink_cc_library(
  NAME parameters
  SRCS
    parameters.h
)

tink_cc_library(
  NAME key
  SRCS
    key.h
  DEPS
    tink::core::parameters
    absl::optional
)

tink_cc_library(
  NAME private_key
  SRCS
    private_key.h
  DEPS
    tink::core::key
)

tink_cc_library(
  NAME partial_key_access_token
  SRCS
    partial_key_access_token.h
  PUBLIC
)

tink_cc_library(
  NAME partial_key_access
  SRCS
    partial_key_access.h
  DEPS
    tink::core::partial_key_access_token
  PUBLIC
)

tink_cc_library(
  NAME secret_key_access_token
  SRCS
    secret_key_access_token.h
)

tink_cc_library(
  NAME insecure_secret_key_access
  SRCS
    insecure_secret_key_access.h
  DEPS
    tink::core::secret_key_access_token
)

add_library(tink::core::insecure_secret_key_access_testonly ALIAS tink_internal_core_insecure_secret_key_access)

tink_cc_library(
  NAME restricted_data
  SRCS
    core/restricted_data.cc
    restricted_data.h
  DEPS
    tink::core::secret_key_access_token
    absl::check
    absl::string_view
    tink::subtle::random
    tink::util::secret_data
)

tink_cc_library(
  NAME key_status
  SRCS
    key_status.h
)

tink_cc_library(
  NAME configuration
  SRCS
    configuration.h
  DEPS
    tink::internal::configuration_helper
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
)

tink_cc_library(
  NAME key_gen_configuration
  SRCS
    key_gen_configuration.h
  DEPS
    tink::core::key
    tink::core::parameters
    absl::flat_hash_map
    absl::any_invocable
    absl::optional
    tink::internal::key_type_info_store
    tink::util::statusor
)

tink_cc_library(
  NAME big_integer
  SRCS
    core/big_integer.cc
    big_integer.h
  DEPS
    absl::string_view
    crypto
)

tink_cc_library(
  NAME restricted_big_integer
  SRCS
    core/restricted_big_integer.cc
    restricted_big_integer.h
  DEPS
    tink::core::secret_key_access_token
    absl::string_view
    crypto
    tink::internal::call_with_core_dump_protection
    tink::util::secret_data
)

tink_cc_library(
  NAME ec_point
  SRCS
    ec_point.h
  DEPS
    tink::core::big_integer
)

tink_cc_library(
  NAME proto_parameters_format
  SRCS
    core/proto_parameters_format.cc
    proto_parameters_format.h
  DEPS
    tink::core::parameters
    absl::status
    absl::statusor
    absl::strings
    tink::internal::legacy_proto_parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::util::statusor
)

tink_cc_library(
  NAME proto_keyset_format
  SRCS
    core/proto_keyset_format.cc
    proto_keyset_format.h
  DEPS
    tink::core::aead
    tink::core::binary_keyset_reader
    tink::core::binary_keyset_writer
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::keyset_reader
    tink::core::secret_key_access_token
    absl::memory
    absl::status
    absl::strings
    tink::internal::call_with_core_dump_protection
    tink::internal::secret_buffer
    tink::util::secret_data
    tink::util::secret_proto
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

# tests

tink_cc_test(
  NAME version_test
  SRCS
    core/version_test.cc
  DEPS
    tink::core::version
    gmock
    tink::internal::util
)

tink_cc_test(
  NAME binary_keyset_reader_test
  SRCS
    core/binary_keyset_reader_test.cc
  DEPS
    tink::core::binary_keyset_reader
    gmock
    absl::status
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME binary_keyset_writer_test
  SRCS
    core/binary_keyset_writer_test.cc
  DEPS
    tink::core::aead
    tink::core::binary_keyset_writer
    tink::core::insecure_secret_key_access_testonly
    tink::core::keyset_handle
    tink::core::proto_keyset_format
    gmock
    absl::memory
    absl::status
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::config::global_registry
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME crypto_format_test
  SRCS
    core/crypto_format_test.cc
  DEPS
    tink::core::crypto_format
    gmock
    absl::status
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_handle_test
  SRCS
    core/keyset_handle_test.cc
  DEPS
    tink::core::aead
    tink::core::binary_keyset_reader
    tink::core::binary_keyset_writer
    tink::core::cleartext_keyset_handle_testonly
    tink::core::configuration
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::insecure_secret_key_access
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::keyset_reader
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::core::restricted_data
    gmock
    absl::flat_hash_map
    absl::check
    absl::memory
    absl::status
    absl::strings
    absl::optional
    tink::aead::aead_config
    tink::aead::aead_key_templates
    tink::aead::aead_wrapper
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_parameters
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_parameters
    tink::aead::internal::key_gen_config_v0
    tink::config::fips_140_2
    tink::config::global_registry
    tink::config::key_gen_fips_140_2
    tink::config::tink_config
    tink::internal::configuration_impl
    tink::internal::fips_utils
    tink::internal::key_gen_configuration_impl
    tink::internal::mutable_serialization_registry
    tink::internal::ssl_util
    tink::signature::ecdsa_proto_serialization
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::signature_key_templates
    tink::subtle::random
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::status
    tink::util::statusor
    tink::util::test_keyset_handle
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_gcm_siv_cc_proto
    tink::proto::ecdsa_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME keyset_handle_builder_test
  SRCS
    core/keyset_handle_builder_test.cc
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::insecure_secret_key_access_testonly
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::mac
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::core::restricted_data
    gmock
    absl::flat_hash_map
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::aead::aes_gcm_parameters
    tink::aead::aes_gcm_siv_key
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::aes_gcm_siv_parameters
    tink::aead::xchacha20_poly1305_key
    tink::aead::xchacha20_poly1305_key_manager
    tink::aead::xchacha20_poly1305_parameters
    tink::config::global_registry
    tink::config::tink_config
    tink::internal::key_gen_configuration_impl
    tink::internal::legacy_proto_key
    tink::internal::legacy_proto_parameters
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    tink::mac::aes_cmac_key
    tink::mac::aes_cmac_parameters
    tink::mac::mac_key_templates
    tink::subtle::random
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_cmac_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME key_manager_test
  SRCS
    core/key_manager_test.cc
  DEPS
    tink::core::key_manager
    gmock
    absl::status
    tink::util::status
    tink::util::test_matchers
    tink::proto::empty_cc_proto
)

tink_cc_test(
  NAME keyset_manager_test
  SRCS
    core/keyset_manager_test.cc
  DEPS
    tink::core::keyset_handle
    tink::core::keyset_manager
    gmock
    absl::status
    tink::aead::aead_config
    tink::aead::aes_gcm_key_manager
    tink::util::test_keyset_handle
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME cleartext_keyset_handle_test
  SRCS
    core/cleartext_keyset_handle_test.cc
  DEPS
    tink::core::binary_keyset_reader
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    gmock
    absl::status
    tink::util::status
    tink::util::test_keyset_handle
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME primitive_set_test
  SRCS
    core/primitive_set_test.cc
  DEPS
    tink::core::crypto_format
    tink::core::mac
    tink::core::primitive_set
    gmock
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    tink::keyderivation::keyset_deriver
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME kms_clients_test
  SRCS
    core/kms_clients_test.cc
  DEPS
    tink::core::aead
    tink::core::kms_client
    tink::core::kms_clients
    gmock
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME template_util_test
  SRCS
    core/template_util_test.cc
  DEPS
    tink::core::template_util
    gmock
)

tink_cc_test(
  NAME key_type_manager_test
  SRCS
    core/key_type_manager_test.cc
  DEPS
    tink::core::aead
    tink::core::key_type_manager
    tink::core::template_util
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::subtle::subtle
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::validation
    tink::proto::aes_gcm_cc_proto
)

tink_cc_test(
  NAME key_manager_impl_test
  SRCS
    core/key_manager_impl_test.cc
  DEPS
    tink::core::aead
    tink::core::key_manager_impl
    gmock
    absl::status
    absl::string_view
    tink::subtle::subtle
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::util::validation
    tink::proto::aes_gcm_cc_proto
)

tink_cc_test(
  NAME private_key_manager_impl_test
  SRCS
    core/private_key_manager_impl_test.cc
  DEPS
    tink::core::key_manager_impl
    tink::core::key_type_manager
    tink::core::private_key_manager_impl
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::key_manager
    tink::core::registry
    gmock
    absl::memory
    absl::status
    tink::subtle::aes_gcm_boringssl
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::util::validation
    tink::proto::ecdsa_cc_proto
)

tink_cc_test(
  NAME key_access_test
  SRCS
    core/key_access_test.cc
  DEPS
    tink::core::key_access
    tink::core::secret_key_access_testonly
    gmock
)

tink_cc_test(
  NAME partial_key_access_token_test
  SRCS
    core/partial_key_access_token_test.cc
  DEPS
    tink::core::partial_key_access
    tink::core::partial_key_access_token
    gmock
    absl::core_headers
)

tink_cc_test(
  NAME restricted_data_test
  SRCS
    core/restricted_data_test.cc
  DEPS
    tink::core::insecure_secret_key_access_testonly
    tink::core::restricted_data
    gmock
    tink::subtle::random
)

tink_cc_test(
  NAME proto_keyset_format_test
  SRCS
    core/proto_keyset_format_test.cc
  DEPS
    tink::core::aead
    tink::core::binary_keyset_reader
    tink::core::binary_keyset_writer
    tink::core::insecure_secret_key_access_testonly
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::keyset_reader
    tink::core::mac
    tink::core::proto_keyset_format
    tink::core::secret_data
    gmock
    absl::memory
    absl::statusor
    tink::aead::aes_gcm_parameters
    tink::config::global_registry
    tink::config::tink_config
    tink::mac::aes_cmac_parameters
    tink::signature::ed25519_parameters
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME big_integer_test
  SRCS
    core/big_integer_test.cc
  DEPS
    tink::core::big_integer
    gmock
    absl::string_view
    tink::util::test_util
)

tink_cc_test(
  NAME restricted_big_integer_test
  SRCS
    core/restricted_big_integer_test.cc
  DEPS
    tink::core::insecure_secret_key_access_testonly
    tink::core::restricted_big_integer
    gmock
    absl::string_view
    tink::util::secret_data
    tink::util::test_util
)

tink_cc_test(
  NAME ec_point_test
  SRCS
    core/ec_point_test.cc
  DEPS
    tink::core::big_integer
    tink::core::ec_point
    gmock
    tink::subtle::random
)

tink_cc_test(
  NAME proto_parameters_format_test
  SRCS
    core/proto_parameters_format_test.cc
  DEPS
    tink::core::parameters
    tink::core::proto_parameters_format
    gmock
    absl::status
    tink::internal::legacy_proto_parameters
    tink::internal::proto_parameters_serialization
    tink::mac::aes_cmac_parameters
    tink::mac::aes_cmac_proto_serialization
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_cmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME secret_data
  SRCS
    secret_data.h
  DEPS
    tink::internal::sanitizing_allocator
    tink::util::secret_data_internal_class
  PUBLIC
)

tink_cc_test(
  NAME secret_data_test
  SRCS
    secret_data_test.cc
  DEPS
    tink::core::secret_data
    gmock
    absl::string_view
    benchmark::benchmark_main
    tink::internal::secret_buffer
    tink::util::secret_data
)
