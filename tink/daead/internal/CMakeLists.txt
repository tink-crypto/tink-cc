tink_module(daead::internal)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_wrapper
    tink::internal::configuration_impl
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
    tink::daead::aes_siv_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
)

tink_cc_library(
  NAME aes_siv_proto_serialization_impl
  SRCS
    aes_siv_proto_serialization_impl.cc
    aes_siv_proto_serialization_impl.h
  DEPS
    tink::daead::internal::aes_siv_proto_format
    absl::core_headers
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_data
    tink::core::secret_key_access_token
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::proto_parser_message
    tink::internal::proto_parser_owning_fields
    tink::internal::proto_parser_secret_data_owning_field
    tink::internal::serialization_registry
    tink::internal::tink_proto_structs
    tink::util::status
)

# tests

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::daead::internal::config_v0
    tink::daead::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::deterministic_aead
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::daead::aes_siv_key_manager
    tink::daead::deterministic_aead_key_templates
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME aes_siv_proto_serialization_impl_test
  SRCS
    aes_siv_proto_serialization_impl_test.cc
  DEPS
    tink::daead::internal::aes_siv_proto_serialization_impl
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
    tink::daead::aes_siv_key
    tink::daead::aes_siv_parameters
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::serialization_registry
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::proto::aes_siv_cc_proto
)

tink_cc_library(
  NAME aes_siv_proto_format
  SRCS
    aes_siv_proto_format.h
  DEPS
    tink::internal::proto_parser_message
    tink::internal::proto_parser_owning_fields
    tink::internal::proto_parser_secret_data_owning_field
)

tink_cc_test(
  NAME aes_siv_proto_format_test
  SRCS
    aes_siv_proto_format_test.cc
  DEPS
    tink::daead::internal::aes_siv_proto_format
    gmock
    absl::strings
    tink::internal::testing::field_with_number
)
