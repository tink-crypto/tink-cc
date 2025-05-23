tink_cc_library(
  NAME cecpq2_aead_hkdf_dem_helper
  SRCS
    cecpq2_aead_hkdf_dem_helper.cc
    cecpq2_aead_hkdf_dem_helper.h
  DEPS
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::core::aead
    tink::core::deterministic_aead
    tink::core::registry
    tink::daead::subtle::aead_or_daead
    tink::internal::registry_impl
    tink::util::errors
    tink::util::istream_input_stream
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME cecpq2_aead_hkdf_dem_helper_test
  SRCS
    cecpq2_aead_hkdf_dem_helper_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_dem_helper
    gmock
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::core::registry
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::config::tink_config
    tink::daead::aes_siv_key_manager
    tink::daead::subtle::aead_or_daead
    tink::util::secret_data
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_library(
  NAME cecpq2_aead_hkdf_private_key_manager
  SRCS
    cecpq2_aead_hkdf_private_key_manager.cc
    cecpq2_aead_hkdf_private_key_manager.h
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_dem_helper
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_public_key_manager
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::hybrid_decrypt
    tink::experimental::pqcrypto::kem::subtle::cecpq2_aead_hkdf_hybrid_decrypt
    tink::experimental::pqcrypto::kem::subtle::cecpq2_subtle_boringssl_util
    tink::subtle::common_enums
    tink::subtle::random
    tink::subtle::subtle_util
    tink::util::enums
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::tink_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_test(
  NAME cecpq2_aead_hkdf_private_key_manager_test
  SRCS
    cecpq2_aead_hkdf_private_key_manager_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_private_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_public_key_manager
    gmock
    absl::memory
    absl::status
    tink::core::hybrid_decrypt
    tink::core::registry
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::experimental::pqcrypto::kem::subtle::cecpq2_aead_hkdf_hybrid_encrypt
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME cecpq2_aead_hkdf_public_key_manager
  SRCS
    cecpq2_aead_hkdf_public_key_manager.cc
    cecpq2_aead_hkdf_public_key_manager.h
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_dem_helper
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::hybrid_encrypt
    tink::experimental::pqcrypto::kem::subtle::cecpq2_aead_hkdf_hybrid_encrypt
    tink::util::enums
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_test(
  NAME cecpq2_aead_hkdf_public_key_manager_test
  SRCS
    cecpq2_aead_hkdf_public_key_manager_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_private_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_public_key_manager
    gmock
    absl::status
    tink::core::hybrid_encrypt
    tink::core::registry
    tink::aead::aead_key_templates
    tink::aead::aes_gcm_key_manager
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_eax_cc_proto
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME cecpq2_hybrid_config
  SRCS
    cecpq2_hybrid_config.cc
    cecpq2_hybrid_config.h
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_private_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_public_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_proto_serialization
    absl::core_headers
    absl::memory
    absl::status
    tink::core::registry
    tink::aead::aead_config
    tink::config::tink_fips
    tink::hybrid::hybrid_decrypt_wrapper
    tink::hybrid::hybrid_encrypt_wrapper
    tink::util::status
)

tink_cc_test(
  NAME cecpq2_hybrid_config_test
  SRCS
    cecpq2_hybrid_config_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_private_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_public_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_hybrid_config
    tink::experimental::pqcrypto::kem::cecpq2_hybrid_key_templates
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    tink::experimental::pqcrypto::kem::cecpq2_private_key
    tink::experimental::pqcrypto::kem::cecpq2_public_key
    gmock
    absl::check
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    crypto
    tink::core::crypto_format
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::insecure_secret_key_access_testonly
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::primitive_set
    tink::core::registry
    tink::core::restricted_data
    tink::aead::xchacha20_poly1305_parameters
    tink::config::tink_fips
    tink::experimental::pqcrypto::kem::subtle::cecpq2_subtle_boringssl_util
    tink::internal::ec_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::secret_data
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME cecpq2_hybrid_key_templates
  SRCS
    cecpq2_hybrid_key_templates.cc
    cecpq2_hybrid_key_templates.h
  DEPS
    absl::strings
    tink::aead::aead_key_templates
    tink::daead::deterministic_aead_key_templates
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_test(
  NAME cecpq2_hybrid_key_templates_test
  SRCS
    cecpq2_hybrid_key_templates_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_aead_hkdf_private_key_manager
    tink::experimental::pqcrypto::kem::cecpq2_hybrid_config
    tink::experimental::pqcrypto::kem::cecpq2_hybrid_key_templates
    gmock
    tink::util::test_matchers
    tink::proto::cecpq2_aead_hkdf_cc_proto
)

tink_cc_library(
  NAME ml_kem_parameters
  SRCS
    ml_kem_parameters.cc
    ml_kem_parameters.h
  DEPS
    absl::status
    tink::core::parameters
    tink::experimental::kem::kem_parameters
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME ml_kem_parameters_test
  SRCS
    ml_kem_parameters_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    gmock
    absl::status
    tink::core::parameters
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME ml_kem_private_key
  SRCS
    ml_kem_private_key.cc
    ml_kem_private_key.h
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_public_key
    absl::core_headers
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    crypto
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::experimental::kem::kem_private_key
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME ml_kem_private_key_test
  SRCS
    ml_kem_private_key_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    tink::experimental::pqcrypto::kem::ml_kem_private_key
    tink::experimental::pqcrypto::kem::ml_kem_public_key
    gmock
    absl::status
    absl::strings
    absl::optional
    crypto
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::internal::secret_buffer
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME ml_kem_public_key
  SRCS
    ml_kem_public_key.cc
    ml_kem_public_key.h
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    absl::core_headers
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access_token
    tink::experimental::kem::kem_public_key
    tink::internal::output_prefix_util
    tink::util::status
    tink::util::statusor
)

tink_cc_test(
  NAME ml_kem_public_key_test
  SRCS
    ml_kem_public_key_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    tink::experimental::pqcrypto::kem::ml_kem_public_key
    gmock
    absl::status
    absl::strings
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_library(
  NAME ml_kem_proto_serialization
  SRCS
    ml_kem_proto_serialization.cc
    ml_kem_proto_serialization.h
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    tink::experimental::pqcrypto::kem::ml_kem_private_key
    tink::experimental::pqcrypto::kem::ml_kem_public_key
    absl::no_destructor
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::internal::key_parser
    tink::internal::key_serializer
    tink::internal::mutable_serialization_registry
    tink::internal::parameters_parser
    tink::internal::parameters_serializer
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::proto_parser
    tink::internal::tink_proto_structs
    tink::util::secret_data
    tink::util::status
)

tink_cc_test(
  NAME ml_kem_proto_serialization_test
  SRCS
    ml_kem_proto_serialization_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::ml_kem_parameters
    tink::experimental::pqcrypto::kem::ml_kem_private_key
    tink::experimental::pqcrypto::kem::ml_kem_proto_serialization
    tink::experimental::pqcrypto::kem::ml_kem_public_key
    gmock
    absl::check
    absl::status
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access_testonly
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::experimental::pqcrypto::kem::internal::ml_kem_test_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::ml_kem_cc_proto
)

tink_cc_library(
  NAME cecpq2_parameters
  SRCS
    cecpq2_parameters.cc
    cecpq2_parameters.h
  DEPS
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::aead::aes_gcm_parameters
    tink::aead::xchacha20_poly1305_parameters
    tink::daead::aes_siv_parameters
    tink::hybrid::hybrid_parameters
)

tink_cc_test(
  NAME cecpq2_parameters_test
  SRCS
    cecpq2_parameters_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    gmock
    absl::check
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::parameters
    tink::aead::aes_gcm_parameters
    tink::aead::chacha20_poly1305_parameters
    tink::aead::xchacha20_poly1305_parameters
    tink::daead::aes_siv_parameters
    tink::util::test_matchers
)

tink_cc_library(
  NAME cecpq2_public_key
  SRCS
    cecpq2_public_key.cc
    cecpq2_public_key.h
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::string_view
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access_token
    tink::hybrid::hybrid_public_key
    tink::internal::ec_util
    tink::internal::output_prefix_util
)

tink_cc_test(
  NAME cecpq2_public_key_test
  SRCS
    cecpq2_public_key_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    tink::experimental::pqcrypto::kem::cecpq2_public_key
    gmock
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access
    tink::aead::xchacha20_poly1305_parameters
    tink::internal::ec_util
    tink::subtle::random
    tink::util::test_matchers
)

tink_cc_library(
  NAME cecpq2_private_key
  SRCS
    cecpq2_private_key.cc
    cecpq2_private_key.h
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_public_key
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    crypto
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::experimental::pqcrypto::kem::subtle::cecpq2_subtle_boringssl_util
    tink::hybrid::hybrid_private_key
    tink::internal::ec_util
    tink::internal::internal_insecure_secret_key_access
)

tink_cc_test(
  NAME cecpq2_private_key_test
  SRCS
    cecpq2_private_key_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    tink::experimental::pqcrypto::kem::cecpq2_private_key
    tink::experimental::pqcrypto::kem::cecpq2_public_key
    gmock
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::insecure_secret_key_access_testonly
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::xchacha20_poly1305_parameters
    tink::experimental::pqcrypto::kem::subtle::cecpq2_subtle_boringssl_util
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::test_matchers
)

tink_cc_library(
  NAME cecpq2_proto_serialization
  SRCS
    cecpq2_proto_serialization.h
  DEPS
    absl::status
    tink::experimental::pqcrypto::kem::internal::cecpq2_proto_serialization_impl
    tink::internal::mutable_serialization_registry
)

tink_cc_test(
  NAME cecpq2_proto_serialization_test
  SRCS
    cecpq2_proto_serialization_test.cc
  DEPS
    tink::experimental::pqcrypto::kem::cecpq2_parameters
    tink::experimental::pqcrypto::kem::cecpq2_private_key
    tink::experimental::pqcrypto::kem::cecpq2_proto_serialization
    tink::experimental::pqcrypto::kem::cecpq2_public_key
    gmock
    absl::check
    absl::statusor
    absl::string_view
    absl::optional
    crypto
    tink::core::insecure_secret_key_access_testonly
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::aead::xchacha20_poly1305_parameters
    tink::experimental::pqcrypto::kem::subtle::cecpq2_subtle_boringssl_util
    tink::internal::ec_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::common_enums
    tink::subtle::random
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
    tink::proto::cecpq2_aead_hkdf_cc_proto
)
