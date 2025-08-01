tink_module(jwt)

add_subdirectory(internal)

tink_cc_library(
  NAME raw_jwt
  SRCS
    raw_jwt.cc
    raw_jwt.h
  DEPS
    protobuf::libprotobuf
    absl::status
    absl::statusor
    absl::strings
    absl::time
    absl::optional
    tink::jwt::internal::json_util
)

tink_cc_library(
  NAME jwt_validator
  SRCS
    jwt_validator.cc
    jwt_validator.h
  DEPS
    tink::jwt::raw_jwt
    absl::status
    absl::statusor
    absl::strings
    absl::time
    absl::optional
)

tink_cc_library(
  NAME verified_jwt
  SRCS
    verified_jwt.cc
    verified_jwt.h
  DEPS
    tink::jwt::raw_jwt
    absl::statusor
    absl::strings
    absl::time
)

tink_cc_library(
  NAME jwt_mac
  SRCS
    jwt_mac.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    absl::statusor
    absl::strings
)

tink_cc_library(
  NAME jwt_public_key_sign
  SRCS
    jwt_public_key_sign.h
  DEPS
    tink::jwt::raw_jwt
    absl::statusor
)

tink_cc_library(
  NAME jwt_public_key_verify
  SRCS
    jwt_public_key_verify.h
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::verified_jwt
    absl::statusor
    absl::strings
)

tink_cc_library(
  NAME jwk_set_converter
  SRCS
    jwk_set_converter.cc
    jwk_set_converter.h
  DEPS
    protobuf::libprotobuf
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    absl::optional
    crypto
    tink::core::binary_keyset_writer
    tink::core::keyset_handle
    tink::internal::ec_util
    tink::internal::ssl_unique_ptr
    tink::jwt::internal::json_util
    tink::jwt::internal::jwt_format
    tink::subtle::common_enums
    tink::util::keyset_util
    tink::proto::ed25519_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME jwt_mac_config
  SRCS
    jwt_mac_config.cc
    jwt_mac_config.h
  DEPS
    tink::jwt::jwt_hmac_proto_serialization
    absl::memory
    absl::status
    tink::core::registry
    tink::config::tink_fips
    tink::jwt::internal::jwt_hmac_key_manager
    tink::jwt::internal::jwt_mac_wrapper
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME jwt_signature_config
  SRCS
    jwt_signature_config.cc
    jwt_signature_config.h
  DEPS
    tink::jwt::jwt_ecdsa_proto_serialization
    tink::jwt::jwt_rsa_ssa_pkcs1_proto_serialization
    tink::jwt::jwt_rsa_ssa_pss_proto_serialization
    absl::memory
    absl::status
    tink::core::registry
    tink::config::tink_fips
    tink::jwt::internal::jwt_ecdsa_sign_key_manager
    tink::jwt::internal::jwt_ecdsa_verify_key_manager
    tink::jwt::internal::jwt_public_key_sign_wrapper
    tink::jwt::internal::jwt_public_key_verify_wrapper
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_verify_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_sign_key_manager
    tink::jwt::internal::jwt_rsa_ssa_pss_verify_key_manager
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME jwt_key_templates
  SRCS
    jwt_key_templates.cc
    jwt_key_templates.h
  DEPS
    absl::statusor
    crypto
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_hmac_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_library(
  NAME jwt_mac_parameters
  SRCS
    jwt_mac_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME jwt_mac_key
  SRCS
    jwt_mac_key.h
  DEPS
    tink::jwt::jwt_mac_parameters
    absl::optional
    tink::core::key
)

tink_cc_library(
  NAME jwt_hmac_parameters
  SRCS
    jwt_hmac_parameters.cc
    jwt_hmac_parameters.h
  DEPS
    tink::jwt::jwt_mac_parameters
    absl::status
    absl::statusor
    absl::strings
    tink::core::parameters
)

tink_cc_library(
  NAME jwt_hmac_key
  SRCS
    jwt_hmac_key.cc
    jwt_hmac_key.h
  DEPS
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_mac_key
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_data
    tink::internal::endian
)

tink_cc_library(
  NAME jwt_hmac_proto_serialization
  SRCS
    jwt_hmac_proto_serialization.cc
    jwt_hmac_proto_serialization.h
  DEPS
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    absl::no_destructor
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
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
)

tink_cc_library(
  NAME jwt_signature_parameters
  SRCS
    jwt_signature_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME jwt_signature_public_key
  SRCS
    jwt_signature_public_key.h
  DEPS
    tink::jwt::jwt_signature_parameters
    absl::optional
    tink::core::key
)

tink_cc_library(
  NAME jwt_signature_private_key
  SRCS
    jwt_signature_private_key.h
  DEPS
    tink::jwt::jwt_signature_parameters
    tink::jwt::jwt_signature_public_key
    absl::optional
    tink::core::key
    tink::core::private_key
)

tink_cc_library(
  NAME jwt_ecdsa_parameters
  SRCS
    jwt_ecdsa_parameters.cc
    jwt_ecdsa_parameters.h
  DEPS
    tink::jwt::jwt_signature_parameters
    absl::status
    absl::statusor
    tink::core::parameters
)

tink_cc_library(
  NAME jwt_ecdsa_public_key
  SRCS
    jwt_ecdsa_public_key.cc
    jwt_ecdsa_public_key.h
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_signature_public_key
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::ec_point
    tink::core::key
    tink::core::partial_key_access_token
    tink::internal::ec_util
    tink::internal::endian
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
)

tink_cc_library(
  NAME jwt_ecdsa_private_key
  SRCS
    jwt_ecdsa_private_key.cc
    jwt_ecdsa_private_key.h
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_public_key
    tink::jwt::jwt_signature_private_key
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_big_integer
    tink::internal::bn_util
    tink::internal::call_with_core_dump_protection
    tink::internal::ec_util
    tink::internal::err_util
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
)

tink_cc_library(
  NAME jwt_ecdsa_proto_serialization
  SRCS
    jwt_ecdsa_proto_serialization.cc
    jwt_ecdsa_proto_serialization.h
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_ecdsa_public_key
    absl::no_destructor
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::core::secret_key_access_token
    tink::internal::bn_encoding_util
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
)

tink_cc_library(
  NAME jwt_rsa_ssa_pkcs1_parameters
  SRCS
    jwt_rsa_ssa_pkcs1_parameters.cc
    jwt_rsa_ssa_pkcs1_parameters.h
  DEPS
    tink::jwt::jwt_signature_parameters
    absl::flat_hash_set
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::parameters
    tink::internal::bn_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
)

tink_cc_library(
  NAME jwt_rsa_ssa_pkcs1_public_key
  SRCS
    jwt_rsa_ssa_pkcs1_public_key.cc
    jwt_rsa_ssa_pkcs1_public_key.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_signature_public_key
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::key
    tink::core::partial_key_access_token
    tink::internal::endian
)

tink_cc_library(
  NAME jwt_rsa_ssa_pkcs1_private_key
  SRCS
    jwt_rsa_ssa_pkcs1_private_key.cc
    jwt_rsa_ssa_pkcs1_private_key.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    tink::jwt::jwt_signature_private_key
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_big_integer
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
)

tink_cc_library(
  NAME jwt_rsa_ssa_pkcs1_proto_serialization
  SRCS
    jwt_rsa_ssa_pkcs1_proto_serialization.cc
    jwt_rsa_ssa_pkcs1_proto_serialization.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    absl::no_destructor
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::core::secret_data
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
)

tink_cc_library(
  NAME jwt_rsa_ssa_pss_parameters
  SRCS
    jwt_rsa_ssa_pss_parameters.cc
    jwt_rsa_ssa_pss_parameters.h
  DEPS
    tink::jwt::jwt_signature_parameters
    absl::flat_hash_set
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::parameters
    tink::internal::bn_util
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
)

tink_cc_library(
  NAME jwt_rsa_ssa_pss_public_key
  SRCS
    jwt_rsa_ssa_pss_public_key.cc
    jwt_rsa_ssa_pss_public_key.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_signature_public_key
    absl::status
    absl::statusor
    absl::strings
    absl::str_format
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::key
    tink::core::partial_key_access_token
    tink::internal::endian
)

tink_cc_library(
  NAME jwt_rsa_ssa_pss_private_key
  SRCS
    jwt_rsa_ssa_pss_private_key.cc
    jwt_rsa_ssa_pss_private_key.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_public_key
    tink::jwt::jwt_signature_private_key
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access_token
    tink::core::restricted_big_integer
    tink::internal::rsa_util
    tink::internal::ssl_unique_ptr
)

tink_cc_library(
  NAME jwt_rsa_ssa_pss_proto_serialization
  SRCS
    jwt_rsa_ssa_pss_proto_serialization.cc
    jwt_rsa_ssa_pss_proto_serialization.h
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
    tink::jwt::jwt_rsa_ssa_pss_public_key
    absl::no_destructor
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::core::secret_data
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
)

tink_cc_library(
  NAME jwt_mac_config_v0
  SRCS
    jwt_mac_config_v0.cc
    jwt_mac_config_v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::jwt::internal::jwt_mac_config_v0
)

tink_cc_library(
  NAME jwt_mac_key_gen_config_v0
  SRCS
    jwt_mac_key_gen_config_v0.cc
    jwt_mac_key_gen_config_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::jwt::internal::jwt_mac_key_gen_config_v0
)

tink_cc_library(
  NAME jwt_signature_config_v0
  SRCS
    jwt_signature_config_v0.cc
    jwt_signature_config_v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::jwt::internal::jwt_signature_config_v0
)

tink_cc_library(
  NAME jwt_signature_key_gen_config_v0
  SRCS
    jwt_signature_key_gen_config_v0.cc
    jwt_signature_key_gen_config_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::jwt::internal::jwt_signature_key_gen_config_v0
)

# tests

tink_cc_test(
  NAME raw_jwt_test
  SRCS
    raw_jwt_test.cc
  DEPS
    tink::jwt::raw_jwt
    gmock
    absl::statusor
    absl::time
    tink::util::test_matchers
)

tink_cc_test(
  NAME verified_jwt_test
  SRCS
    verified_jwt_test.cc
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    gmock
    absl::status
    absl::statusor
    absl::strings
    absl::time
    absl::optional
    tink::core::mac
    tink::jwt::internal::jwt_mac_impl
    tink::jwt::internal::jwt_mac_internal
    tink::subtle::hmac_boringssl
    tink::util::enums
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::common_cc_proto
)

tink_cc_test(
  NAME jwt_validator_test
  SRCS
    jwt_validator_test.cc
  DEPS
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    gmock
    absl::statusor
    absl::time
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_key_templates_test
  SRCS
    jwt_key_templates_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac
    tink::jwt::jwt_mac_config
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    gmock
    absl::statusor
    tink::core::keyset_handle
    tink::config::global_registry
    tink::util::test_matchers
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME jwk_set_converter_test
  SRCS
    jwk_set_converter_test.cc
  DEPS
    tink::jwt::jwk_set_converter
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_signature_config
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    protobuf::libprotobuf
    gmock
    absl::status
    absl::statusor
    absl::strings
    crypto
    tink::core::cleartext_keyset_handle
    tink::core::keyset_handle
    tink::core::keyset_reader
    tink::config::global_registry
    tink::json::json_keyset_reader
    tink::jwt::internal::json_util
    tink::util::test_matchers
    tink::proto::ecdsa_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME jwt_signature_config_test
  SRCS
    jwt_signature_config_test.cc
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_ecdsa_public_key
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
    tink::jwt::jwt_rsa_ssa_pss_public_key
    tink::jwt::jwt_signature_config
    gmock
    absl::check
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::keyset_handle
    tink::core::partial_key_access
    tink::core::registry
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::config::global_registry
    tink::internal::ec_util
    tink::internal::fips_utils
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::tink_proto_structs
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::jwt_ecdsa_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
)

tink_cc_test(
  NAME jwt_mac_config_test
  SRCS
    jwt_mac_config_test.cc
  DEPS
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac_config
    gmock
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::keyset_handle
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::registry
    tink::core::restricted_data
    tink::config::global_registry
    tink::internal::fips_utils
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::random
    tink::util::test_matchers
    tink::proto::jwt_hmac_cc_proto
)

tink_cc_test(
  NAME jwt_hmac_parameters_test
  SRCS
    jwt_hmac_parameters_test.cc
  DEPS
    tink::jwt::jwt_hmac_parameters
    gmock
    absl::status
    absl::statusor
    tink::core::parameters
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_hmac_key_test
  SRCS
    jwt_hmac_key_test.cc
  DEPS
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_hmac_proto_serialization_test
  SRCS
    jwt_hmac_proto_serialization_test.cc
  DEPS
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_hmac_proto_serialization
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
    tink::proto::jwt_hmac_cc_proto
)

tink_cc_test(
  NAME jwt_ecdsa_parameters_test
  SRCS
    jwt_ecdsa_parameters_test.cc
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    gmock
    absl::status
    absl::statusor
    tink::core::parameters
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_ecdsa_public_key_test
  SRCS
    jwt_ecdsa_public_key_test.cc
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_public_key
    gmock
    absl::status
    absl::statusor
    absl::optional
    tink::core::big_integer
    tink::core::ec_point
    tink::core::key
    tink::core::partial_key_access
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME jwt_ecdsa_private_key_test
  SRCS
    jwt_ecdsa_private_key_test.cc
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_ecdsa_public_key
    gmock
    absl::status
    absl::statusor
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_ecdsa_proto_serialization_test
  SRCS
    jwt_ecdsa_proto_serialization_test.cc
  DEPS
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_ecdsa_proto_serialization
    tink::jwt::jwt_ecdsa_public_key
    gmock
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::internal::ec_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::tink_proto_structs
    tink::subtle::common_enums
    tink::util::secret_data
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::jwt_ecdsa_cc_proto
)

tink_cc_test(
  NAME jwt_rsa_ssa_pkcs1_parameters_test
  SRCS
    jwt_rsa_ssa_pkcs1_parameters_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    gmock
    absl::status
    absl::statusor
    crypto
    tink::core::big_integer
    tink::core::parameters
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_rsa_ssa_pkcs1_public_key_test
  SRCS
    jwt_rsa_ssa_pkcs1_public_key_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    gmock
    absl::check
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::key
    tink::core::partial_key_access
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME jwt_rsa_ssa_pkcs1_private_key_test
  SRCS
    jwt_rsa_ssa_pkcs1_private_key_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    gmock
    absl::check
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_rsa_ssa_pkcs1_proto_serialization_test
  SRCS
    jwt_rsa_ssa_pkcs1_proto_serialization_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
    tink::jwt::jwt_rsa_ssa_pkcs1_proto_serialization
    tink::jwt::jwt_rsa_ssa_pkcs1_public_key
    gmock
    absl::check
    absl::status
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::internal::bn_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::ssl_unique_ptr
    tink::internal::tink_proto_structs
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::jwt_rsa_ssa_pkcs1_cc_proto
)

tink_cc_test(
  NAME jwt_rsa_ssa_pss_parameters_test
  SRCS
    jwt_rsa_ssa_pss_parameters_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    gmock
    absl::status
    absl::statusor
    crypto
    tink::core::big_integer
    tink::core::parameters
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_rsa_ssa_pss_public_key_test
  SRCS
    jwt_rsa_ssa_pss_public_key_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_public_key
    gmock
    absl::check
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    tink::core::big_integer
    tink::core::key
    tink::core::partial_key_access
    tink::util::test_matchers
    tink::util::test_util
)

tink_cc_test(
  NAME jwt_rsa_ssa_pss_private_key_test
  SRCS
    jwt_rsa_ssa_pss_private_key_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
    tink::jwt::jwt_rsa_ssa_pss_public_key
    gmock
    absl::check
    absl::status
    absl::strings
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::internal::bn_util
    tink::internal::ssl_unique_ptr
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_rsa_ssa_pss_proto_serialization_test
  SRCS
    jwt_rsa_ssa_pss_proto_serialization_test.cc
  DEPS
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
    tink::jwt::jwt_rsa_ssa_pss_proto_serialization
    tink::jwt::jwt_rsa_ssa_pss_public_key
    gmock
    absl::check
    absl::status
    absl::string_view
    absl::optional
    crypto
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::key
    tink::core::parameters
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::internal::bn_util
    tink::internal::mutable_serialization_registry
    tink::internal::proto_key_serialization
    tink::internal::proto_parameters_serialization
    tink::internal::serialization
    tink::internal::ssl_unique_ptr
    tink::internal::tink_proto_structs
    tink::util::test_matchers
    tink::proto::common_cc_proto
    tink::proto::jwt_rsa_ssa_pss_cc_proto
)

tink_cc_test(
  NAME jwt_mac_config_v0_test
  SRCS
    jwt_mac_config_v0_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_mac
    tink::jwt::jwt_mac_config_v0
    tink::jwt::jwt_mac_key_gen_config_v0
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    gmock
    absl::statusor
    absl::time
    tink::core::keyset_handle
    tink::util::test_matchers
)

tink_cc_test(
  NAME jwt_signature_config_v0_test
  SRCS
    jwt_signature_config_v0_test.cc
  DEPS
    tink::jwt::jwt_key_templates
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_signature_config_v0
    tink::jwt::jwt_signature_key_gen_config_v0
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    gmock
    absl::statusor
    tink::core::keyset_handle
    tink::util::test_matchers
)
