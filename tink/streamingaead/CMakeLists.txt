tink_module(streamingaead)

add_subdirectory(internal)

tink_cc_library(
  NAME streaming_aead_wrapper
  SRCS
    streaming_aead_wrapper.cc
    streaming_aead_wrapper.h
  DEPS
    tink::streamingaead::decrypting_input_stream
    tink::streamingaead::decrypting_random_access_stream
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::core::crypto_format
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME streaming_aead_config
  SRCS
    streaming_aead_config.cc
    streaming_aead_config.h
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_ctr_hmac_streaming_proto_serialization
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_proto_serialization
    tink::streamingaead::streaming_aead_wrapper
    absl::core_headers
    absl::memory
    tink::core::registry
    tink::config::config_util
    tink::config::tink_fips
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME streaming_aead_key_templates
  SRCS
    streaming_aead_key_templates.cc
    streaming_aead_key_templates.h
  DEPS
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_key_manager
  SRCS
    aes_gcm_hkdf_streaming_key_manager.cc
    aes_gcm_hkdf_streaming_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::key_manager
    tink::core::streaming_aead
    tink::subtle::aes_gcm_hkdf_stream_segment_encrypter
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_key_manager
  SRCS
    aes_ctr_hmac_streaming_key_manager.cc
    aes_ctr_hmac_streaming_key_manager.h
  DEPS
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::streaming_aead
    tink::subtle::aes_ctr_hmac_streaming
    tink::subtle::random
    tink::util::constants
    tink::util::enums
    tink::util::errors
    tink::util::input_stream_util
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME buffered_input_stream
  SRCS
    buffered_input_stream.cc
    buffered_input_stream.h
  DEPS
    absl::memory
    absl::status
    tink::core::input_stream
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME shared_input_stream
  SRCS
    shared_input_stream.h
    shared_input_stream.h
  DEPS
    tink::core::input_stream
    tink::util::statusor
)

tink_cc_library(
  NAME shared_random_access_stream
  SRCS
    shared_random_access_stream.h
    shared_random_access_stream.h
  DEPS
    tink::core::random_access_stream
    tink::util::buffer
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME decrypting_input_stream
  SRCS
    decrypting_input_stream.cc
    decrypting_input_stream.h
  DEPS
    tink::streamingaead::buffered_input_stream
    tink::streamingaead::shared_input_stream
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::core::input_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME decrypting_random_access_stream
  SRCS
    decrypting_random_access_stream.cc
    decrypting_random_access_stream.h
  DEPS
    tink::streamingaead::shared_random_access_stream
    absl::core_headers
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    absl::synchronization
    tink::core::primitive_set
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::util::buffer
    tink::util::errors
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::absl_check
    tink::core::configuration
    tink::streamingaead::internal::config_v0
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::absl_check
    tink::core::key_gen_configuration
    tink::streamingaead::internal::key_gen_config_v0
)

tink_cc_library(
  NAME streaming_aead_parameters
  SRCS
    streaming_aead_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME streaming_aead_key
  SRCS
    streaming_aead_key.h
  DEPS
    tink::streamingaead::streaming_aead_parameters
    absl::optional
    tink::core::key
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_parameters
  SRCS
    aes_ctr_hmac_streaming_parameters.cc
    aes_ctr_hmac_streaming_parameters.h
  DEPS
    tink::streamingaead::streaming_aead_parameters
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    tink::core::parameters
    tink::util::statusor
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_key
  SRCS
    aes_ctr_hmac_streaming_key.cc
    aes_ctr_hmac_streaming_key.h
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    tink::streamingaead::streaming_aead_key
    absl::status
    absl::statusor
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_ctr_hmac_streaming_proto_serialization
  SRCS
    aes_ctr_hmac_streaming_proto_serialization.h
  DEPS
    absl::status
    tink::internal::mutable_serialization_registry
    tink::streamingaead::internal::aes_ctr_hmac_streaming_proto_serialization_impl
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_parameters
  SRCS
    aes_gcm_hkdf_streaming_parameters.cc
    aes_gcm_hkdf_streaming_parameters.h
  DEPS
    tink::streamingaead::streaming_aead_parameters
    absl::flat_hash_set
    absl::status
    absl::strings
    absl::optional
    tink::core::parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_key
  SRCS
    aes_gcm_hkdf_streaming_key.cc
    aes_gcm_hkdf_streaming_key.h
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    tink::streamingaead::streaming_aead_key
    absl::status
    absl::statusor
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::util::status
    tink::util::statusor
)

tink_cc_library(
  NAME aes_gcm_hkdf_streaming_proto_serialization
  SRCS
    aes_gcm_hkdf_streaming_proto_serialization.h
  DEPS
    absl::status
    tink::internal::mutable_serialization_registry
    tink::streamingaead::internal::aes_gcm_hkdf_streaming_proto_serialization_impl
)

# tests

tink_cc_test(
  NAME streaming_aead_wrapper_test
  SRCS
    streaming_aead_wrapper_test.cc
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_config
    tink::streamingaead::streaming_aead_wrapper
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::core::insecure_secret_key_access
    tink::core::keyset_handle
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::proto_keyset_format
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::config::global_registry
    tink::internal::test_random_access_stream
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    tink::util::buffer
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_key_manager_test
  SRCS
    aes_gcm_hkdf_streaming_key_manager_test.cc
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_config
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::core::keyset_handle
    tink::core::streaming_aead
    tink::streamingaead::internal::testing::aes_gcm_hkdf_streaming_test_vectors
    tink::streamingaead::internal::testing::streamingaead_test_vector
    tink::subtle::aes_gcm_hkdf_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::aes_eax_cc_proto
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_key_manager_test
  SRCS
    aes_ctr_hmac_streaming_key_manager_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::streaming_aead_config
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::streaming_aead
    tink::config::global_registry
    tink::streamingaead::internal::testing::aes_ctr_hmac_streaming_test_vectors
    tink::streamingaead::internal::testing::streamingaead_test_vector
    tink::subtle::aes_ctr_hmac_streaming
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::streaming_aead_test_util
    tink::subtle::test_util
    tink::util::input_stream_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME streaming_aead_key_templates_test
  SRCS
    streaming_aead_key_templates_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::streaming_aead_key_templates
    gmock
    tink::util::test_matchers
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME streaming_aead_config_test
  SRCS
    streaming_aead_config_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    tink::streamingaead::aes_gcm_hkdf_streaming_key
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    tink::streamingaead::key_gen_config_v0
    tink::streamingaead::streaming_aead_config
    tink::streamingaead::streaming_aead_key_templates
    gmock
    absl::memory
    absl::status
    tink::core::insecure_secret_key_access_testonly
    tink::core::key_status
    tink::core::keyset_handle
    tink::core::keyset_handle_builder
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::registry
    tink::core::restricted_data
    tink::core::streaming_aead
    tink::config::global_registry
    tink::config::tink_fips
    tink::internal::fips_utils
    tink::internal::legacy_proto_key
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::subtle::random
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME buffered_input_stream_test
  SRCS
    buffered_input_stream_test.cc
  DEPS
    tink::streamingaead::buffered_input_stream
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME decrypting_input_stream_test
  SRCS
    decrypting_input_stream_test.cc
  DEPS
    tink::streamingaead::decrypting_input_stream
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::streaming_aead
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME decrypting_random_access_stream_test
  SRCS
    decrypting_random_access_stream_test.cc
  DEPS
    tink::streamingaead::decrypting_random_access_stream
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::output_stream
    tink::core::primitive_set
    tink::core::random_access_stream
    tink::core::streaming_aead
    tink::internal::test_random_access_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::buffer
    tink::util::ostream_output_stream
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME shared_input_stream_test
  SRCS
    shared_input_stream_test.cc
  DEPS
    tink::streamingaead::buffered_input_stream
    tink::streamingaead::shared_input_stream
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::input_stream
    tink::subtle::random
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME shared_random_access_stream_test
  SRCS
    shared_random_access_stream_test.cc
  DEPS
    tink::streamingaead::shared_random_access_stream
    gmock
    absl::memory
    absl::status
    absl::strings
    tink::core::random_access_stream
    tink::internal::test_random_access_stream
    tink::subtle::random
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::streamingaead::config_v0
    tink::streamingaead::key_gen_config_v0
    tink::streamingaead::streaming_aead_key_templates
    gmock
    absl::memory
    tink::core::input_stream
    tink::core::keyset_handle
    tink::core::output_stream
    tink::core::streaming_aead
    tink::subtle::test_util
    tink::util::istream_input_stream
    tink::util::ostream_output_stream
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_parameters_test
  SRCS
    aes_ctr_hmac_streaming_parameters_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    gmock
    absl::status
    absl::statusor
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_key_test
  SRCS
    aes_ctr_hmac_streaming_key_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_ctr_hmac_streaming_proto_serialization_test
  SRCS
    aes_ctr_hmac_streaming_proto_serialization_test.cc
  DEPS
    tink::streamingaead::aes_ctr_hmac_streaming_key
    tink::streamingaead::aes_ctr_hmac_streaming_parameters
    tink::streamingaead::aes_ctr_hmac_streaming_proto_serialization
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
    tink::proto::aes_ctr_hmac_streaming_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_parameters_test
  SRCS
    aes_gcm_hkdf_streaming_parameters_test.cc
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    gmock
    absl::status
    absl::statusor
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_key_test
  SRCS
    aes_gcm_hkdf_streaming_key_test.cc
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_key
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME aes_gcm_hkdf_streaming_proto_serialization_test
  SRCS
    aes_gcm_hkdf_streaming_proto_serialization_test.cc
  DEPS
    tink::streamingaead::aes_gcm_hkdf_streaming_key
    tink::streamingaead::aes_gcm_hkdf_streaming_parameters
    tink::streamingaead::aes_gcm_hkdf_streaming_proto_serialization
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
    tink::proto::aes_gcm_hkdf_streaming_cc_proto
    tink::proto::common_cc_proto
)
