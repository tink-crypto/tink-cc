tink_module(config)

add_subdirectory(internal)

tink_cc_library(
  NAME tink_config
  SRCS
    tink_config.cc
    tink_config.h
  DEPS
    absl::core_headers
    tink::core::key_manager
    tink::core::registry
    tink::daead::deterministic_aead_config
    tink::hybrid::hybrid_config
    tink::prf::prf_config
    tink::signature::signature_config
    tink::streamingaead::streaming_aead_config
    tink::util::status
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME config_util
  SRCS
    config_util.cc
    config_util.h
  DEPS
    tink::proto::config_cc_proto
)

tink_cc_library(
  NAME tink_fips
  SRCS
    tink_fips.cc
    tink_fips.h
  DEPS
    absl::core_headers
    crypto
    tink::internal::fips_utils
    tink::internal::registry_impl
    tink::util::status
)

tink_cc_library(
  NAME global_registry
  SRCS
    global_registry.cc
    global_registry.h
  DEPS
    absl::check
    tink::core::configuration
    tink::core::key_gen_configuration
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
)

tink_cc_library(
  NAME fips_140_2
  SRCS
    fips_140_2.cc
    fips_140_2.h
  DEPS
    absl::check
    absl::memory
    tink::core::configuration
    tink::aead::aead_wrapper
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::internal::configuration_impl
    tink::internal::fips_utils
    tink::mac::hmac_key_manager
    tink::mac::mac_wrapper
    tink::mac::internal::chunked_mac_wrapper
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set_wrapper
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::public_key_sign_wrapper
    tink::signature::public_key_verify_wrapper
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::status
)

tink_cc_library(
  NAME key_gen_fips_140_2
  SRCS
    key_gen_fips_140_2.cc
    key_gen_fips_140_2.h
  DEPS
    absl::check
    absl::memory
    tink::core::key_gen_configuration
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::internal::fips_utils
    tink::internal::key_gen_configuration_impl
    tink::mac::hmac_key_manager
    tink::prf::hmac_prf_key_manager
    tink::signature::ecdsa_sign_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_sign_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_sign_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::status
)

tink_cc_library(
  NAME v0
  SRCS
    v0.cc
    v0.h
  DEPS
    absl::check
    tink::core::configuration
    tink::aead::internal::config_v0
    tink::daead::internal::config_v0
    tink::hybrid::internal::config_v0
    tink::internal::configuration_impl
    tink::mac::internal::config_v0
    tink::prf::internal::config_v0
    tink::signature::internal::config_v0
    tink::streamingaead::internal::config_v0
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME key_gen_v0
  SRCS
    key_gen_v0.cc
    key_gen_v0.h
  DEPS
    absl::check
    tink::core::key_gen_configuration
    tink::aead::internal::key_gen_config_v0
    tink::daead::internal::key_gen_config_v0
    tink::hybrid::internal::key_gen_config_v0
    tink::mac::internal::key_gen_config_v0
    tink::prf::internal::key_gen_config_v0
    tink::signature::internal::key_gen_config_v0
    tink::streamingaead::internal::key_gen_config_v0
  TAGS
    exclude_if_openssl
)

# tests

tink_cc_test(
  NAME tink_config_test
  SRCS
    tink_config_test.cc
  DEPS
    tink::config::tink_config
    gmock
    absl::status
    tink::core::aead
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::mac
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::registry
    tink::core::streaming_aead
    tink::aead::aes_gcm_key_manager
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME config_util_test
  SRCS
    config_util_test.cc
  DEPS
    tink::config::config_util
    gmock
    tink::proto::config_cc_proto
)

tink_cc_test(
  NAME tink_fips_test
  SRCS
    tink_fips_test.cc
  DEPS
    tink::config::tink_fips
    gmock
    absl::status
    crypto
    tink::core::registry
    tink::aead::aead_config
    tink::internal::fips_utils
    tink::util::status
    tink::util::test_matchers
)

tink_cc_test(
  NAME global_registry_test
  SRCS
    global_registry_test.cc
  DEPS
    tink::config::global_registry
    gmock
    absl::memory
    absl::status
    absl::string_view
    tink::core::key_type_manager
    tink::core::template_util
    tink::core::input_stream
    tink::core::keyset_handle
    tink::core::primitive_set
    tink::core::primitive_wrapper
    tink::core::registry
    tink::util::status
    tink::util::statusor
    tink::util::test_matchers
    tink::proto::aes_gcm_cc_proto
    tink::proto::tink_cc_proto
)

tink_cc_test(
  NAME fips_140_2_test
  SRCS
    fips_140_2_test.cc
  DEPS
    tink::config::fips_140_2
    tink::config::key_gen_fips_140_2
    gmock
    absl::status
    tink::core::aead
    tink::core::chunked_mac
    tink::core::keyset_handle
    tink::core::mac
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::internal::configuration_impl
    tink::internal::fips_utils
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set
    tink::signature::ecdsa_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME key_gen_fips_140_2_test
  SRCS
    key_gen_fips_140_2_test.cc
  DEPS
    tink::config::key_gen_fips_140_2
    gmock
    absl::status
    tink::core::keyset_handle
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::internal::fips_utils
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::prf::hmac_prf_key_manager
    tink::signature::ecdsa_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::util::statusor
    tink::util::test_matchers
)

tink_cc_test(
  NAME v0_test
  SRCS
    v0_test.cc
  DEPS
    tink::config::key_gen_v0
    tink::config::v0
    gmock
    tink::core::aead
    tink::core::chunked_mac
    tink::core::configuration
    tink::core::deterministic_aead
    tink::core::hybrid_decrypt
    tink::core::hybrid_encrypt
    tink::core::keyset_handle
    tink::core::mac
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::core::streaming_aead
    tink::aead::aead_key_templates
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_eax_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::aes_gcm_siv_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::daead::aes_siv_key_manager
    tink::hybrid::ecies_aead_hkdf_public_key_manager
    tink::hybrid::internal::hpke_public_key_manager
    tink::internal::configuration_impl
    tink::internal::key_gen_configuration_impl
    tink::internal::key_type_info_store
    tink::internal::keyset_wrapper_store
    tink::mac::aes_cmac_key_manager
    tink::mac::hmac_key_manager
    tink::prf::aes_cmac_prf_key_manager
    tink::prf::hkdf_prf_key_manager
    tink::prf::hmac_prf_key_manager
    tink::prf::prf_set
    tink::signature::ecdsa_verify_key_manager
    tink::signature::ed25519_verify_key_manager
    tink::signature::rsa_ssa_pkcs1_verify_key_manager
    tink::signature::rsa_ssa_pss_verify_key_manager
    tink::streamingaead::aes_ctr_hmac_streaming_key_manager
    tink::streamingaead::aes_gcm_hkdf_streaming_key_manager
    tink::util::statusor
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)
