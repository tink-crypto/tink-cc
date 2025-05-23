tink_module(hybrid::internal)

add_subdirectory(testing)

tink_cc_library(
  NAME hpke_context
  SRCS
    hpke_context.cc
    hpke_context.h
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_util
    absl::memory
    absl::status
    absl::strings
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_context_boringssl
  SRCS
    hpke_context_boringssl.cc
    hpke_context_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::internal::call_with_core_dump_protection
    tink::internal::dfsan_forwarders
    tink::internal::ssl_unique_ptr
    tink::subtle::subtle_util
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_decrypt
  SRCS
    hpke_decrypt.cc
    hpke_decrypt.h
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_util
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    tink::core::hybrid_decrypt
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_encrypt
  SRCS
    hpke_encrypt.cc
    hpke_encrypt.h
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_util
    absl::memory
    absl::status
    absl::strings
    absl::string_view
    tink::core::hybrid_encrypt
    tink::core::partial_key_access
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_public_key
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_key_manager_util
  SRCS
    hpke_key_manager_util.cc
    hpke_key_manager_util.h
  DEPS
    absl::status
    tink::util::status
    tink::util::validation
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_private_key_manager
  SRCS
    hpke_private_key_manager.cc
    hpke_private_key_manager.h
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_key_manager_util
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::core::key_type_manager
    tink::core::private_key_type_manager
    tink::core::template_util
    tink::core::hybrid_decrypt
    tink::core::key_manager
    tink::internal::ec_util
    tink::internal::ssl_unique_ptr
    tink::subtle::common_enums
    tink::util::constants
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::util::validation
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_public_key_manager
  SRCS
    hpke_public_key_manager.cc
    hpke_public_key_manager.h
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_key_manager_util
    absl::memory
    absl::strings
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::hybrid_encrypt
    tink::core::key_manager
    tink::util::constants
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_test_util
  SRCS
    hpke_test_util.cc
    hpke_test_util.h
  DEPS
    tink::hybrid::internal::hpke_util
    absl::status
    absl::strings
    tink::util::status
    tink::util::statusor
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TESTONLY
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_util
  SRCS
    hpke_util.cc
    hpke_util.h
  DEPS
    absl::status
    absl::strings
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME hpke_util_boringssl
  SRCS
    hpke_util_boringssl.cc
    hpke_util_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_util
    absl::status
    absl::strings
    crypto
    tink::util::status
    tink::util::statusor
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME test_hpke_context_boringssl
  SRCS
    test_hpke_context_boringssl.cc
    test_hpke_context_boringssl.h
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    absl::memory
    absl::status
    absl::strings
    crypto
    tink::internal::ssl_unique_ptr
    tink::util::status
    tink::util::statusor
  TESTONLY
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME config_v0
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_private_key_manager
    tink::hybrid::internal::hpke_public_key_manager
    absl::memory
    tink::core::configuration
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_proto_serialization
    tink::hybrid::hpke_public_key
    tink::hybrid::hybrid_decrypt_wrapper
    tink::hybrid::hybrid_encrypt_wrapper
    tink::internal::configuration_impl
    tink::util::status
    tink::util::statusor
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME config_v0_openssl
  SRCS
    config_v0.cc
    config_v0.h
  DEPS
    absl::memory
    tink::core::configuration
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::hybrid_decrypt_wrapper
    tink::hybrid::hybrid_encrypt_wrapper
    tink::internal::configuration_impl
    tink::util::status
  TAGS
    exclude_if_boringssl
)

tink_cc_library(
  NAME key_gen_config_v0
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    tink::hybrid::internal::hpke_private_key_manager
    tink::hybrid::internal::hpke_public_key_manager
    absl::memory
    tink::core::key_gen_configuration
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME key_gen_config_v0_openssl
  SRCS
    key_gen_config_v0.cc
    key_gen_config_v0.h
  DEPS
    absl::memory
    tink::core::key_gen_configuration
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::internal::key_gen_configuration_impl
    tink::util::status
  TAGS
    exclude_if_boringssl
)

# tests

tink_cc_test(
  NAME hpke_context_test
  SRCS
    hpke_context_test.cc
  DEPS
    tink::hybrid::internal::hpke_context
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    absl::status
    absl::strings
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_context_boringssl_test
  SRCS
    hpke_context_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_context_boringssl
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::test_hpke_context_boringssl
    gmock
    absl::status
    crypto
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_decrypt_test
  SRCS
    hpke_decrypt_test.cc
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::check
    absl::status
    absl::strings
    absl::optional
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    tink::hybrid::internal::testing::hpke_test_vectors
    tink::hybrid::internal::testing::hybrid_test_vectors
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_encrypt_test
  SRCS
    hpke_encrypt_test.cc
  DEPS
    tink::hybrid::internal::hpke_decrypt
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    absl::status
    absl::strings
    absl::optional
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    tink::hybrid::internal::testing::hpke_test_vectors
    tink::hybrid::internal::testing::hybrid_test_vectors
    tink::util::secret_data
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_key_manager_util_test
  SRCS
    hpke_key_manager_util_test.cc
  DEPS
    tink::hybrid::internal::hpke_key_manager_util
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    tink::util::status
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_private_key_manager_test
  SRCS
    hpke_private_key_manager_test.cc
  DEPS
    tink::hybrid::internal::hpke_encrypt
    tink::hybrid::internal::hpke_private_key_manager
    gmock
    absl::btree
    absl::status
    absl::strings
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::key_status
    tink::core::keyset_handle
    tink::config::global_registry
    tink::hybrid::hpke_config
    tink::hybrid::hpke_proto_serialization
    tink::hybrid::hybrid_config
    tink::hybrid::internal::testing::hpke_test_vectors
    tink::hybrid::internal::testing::hybrid_test_vectors
    tink::subtle::hybrid_test_util
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_public_key_manager_test
  SRCS
    hpke_public_key_manager_test.cc
  DEPS
    tink::hybrid::internal::hpke_public_key_manager
    tink::hybrid::internal::hpke_test_util
    gmock
    absl::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_util_boringssl_test
  SRCS
    hpke_util_boringssl_test.cc
  DEPS
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    tink::hybrid::internal::hpke_util_boringssl
    gmock
    crypto
    tink::util::statusor
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME hpke_util_test
  SRCS
    hpke_util_test.cc
  DEPS
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::hpke_util
    gmock
    absl::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::hpke_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME config_v0_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::hybrid::internal::config_v0
    tink::hybrid::internal::hpke_private_key_manager
    tink::hybrid::internal::hpke_test_util
    tink::hybrid::internal::key_gen_config_v0
    gmock
    tink::core::configuration
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::key_gen_configuration
    tink::core::key_status
    tink::core::keyset_handle
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::hybrid_key_templates
    tink::hybrid::internal::testing::hpke_test_vectors
    tink::hybrid::internal::testing::hybrid_test_vectors
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME config_v0_openssl_test
  SRCS
    config_v0_test.cc
  DEPS
    tink::hybrid::internal::config_v0_openssl
    tink::hybrid::internal::key_gen_config_v0_openssl
    gmock
    tink::core::configuration
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::key_gen_configuration
    tink::core::keyset_handle
    tink::hybrid::ecies_aead_hkdf_private_key_manager
    tink::hybrid::hybrid_key_templates
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::tink_cc_proto
  TAGS
    exclude_if_boringssl
)

tink_cc_library(
  NAME ecies_aead_hkdf_dem_helper
  SRCS
    ecies_aead_hkdf_dem_helper.cc
    ecies_aead_hkdf_dem_helper.h
  DEPS
    absl::memory
    absl::status
    absl::statusor
    absl::string_view
    tink::core::aead
    tink::core::deterministic_aead
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::daead::subtle::aead_or_daead
    tink::subtle::aes_gcm_boringssl
    tink::subtle::aes_siv_boringssl
    tink::subtle::xchacha20_poly1305_boringssl
    tink::util::errors
    tink::util::protobuf_helper
    tink::util::secret_data
    tink::util::status
    tink::util::statusor
    tink::proto::aes_ctr_cc_proto
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::tink_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
)

tink_cc_test(
  NAME ecies_aead_hkdf_dem_helper_test
  SRCS
    ecies_aead_hkdf_dem_helper_test.cc
  DEPS
    tink::hybrid::internal::ecies_aead_hkdf_dem_helper
    gmock
    absl::status
    absl::string_view
    tink::aead::aes_gcm_key_manager
    tink::daead::aes_siv_key_manager
    tink::daead::subtle::aead_or_daead
    tink::util::secret_data
    tink::util::status
    tink::util::test_matchers
    tink::util::test_util
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::tink_cc_proto
)
