tink_module(signature::subtle)

tink_cc_library(
  NAME composite_ml_dsa_sign_boringssl
  SRCS
    composite_ml_dsa_sign_boringssl.cc
    composite_ml_dsa_sign_boringssl.h
  DEPS
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::low_level_crypto_access_token
    tink::core::public_key_sign
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::ecdsa_private_key
    tink::signature::ed25519_private_key
    tink::signature::rsa_ssa_pkcs1_private_key
    tink::signature::rsa_ssa_pss_private_key
    tink::signature::internal::composite_ml_dsa_util_boringssl
    tink::signature::internal::ml_dsa_sign_boringssl
    tink::subtle::ecdsa_sign_boringssl
    tink::subtle::ed25519_sign_boringssl
    tink::subtle::rsa_ssa_pkcs1_sign_boringssl
    tink::subtle::rsa_ssa_pss_sign_boringssl
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME composite_ml_dsa_sign_boringssl_test
  SRCS
    composite_ml_dsa_sign_boringssl_test.cc
  DEPS
    tink::signature::subtle::composite_ml_dsa_sign_boringssl
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::low_level_crypto_access
    tink::core::public_key_sign
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_util
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME composite_ml_dsa_verify_boringssl
  SRCS
    composite_ml_dsa_verify_boringssl.cc
    composite_ml_dsa_verify_boringssl.h
  DEPS
    absl::status
    absl::statusor
    absl::strings
    absl::string_view
    crypto
    tink::core::low_level_crypto_access_token
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_public_key
    tink::signature::ecdsa_public_key
    tink::signature::ed25519_public_key
    tink::signature::rsa_ssa_pkcs1_public_key
    tink::signature::rsa_ssa_pss_public_key
    tink::signature::internal::composite_ml_dsa_util_boringssl
    tink::signature::internal::ml_dsa_verify_boringssl
    tink::subtle::ecdsa_verify_boringssl
    tink::subtle::ed25519_verify_boringssl
    tink::subtle::rsa_ssa_pkcs1_verify_boringssl
    tink::subtle::rsa_ssa_pss_verify_boringssl
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME composite_ml_dsa_verify_boringssl_test
  SRCS
    composite_ml_dsa_verify_boringssl_test.cc
  DEPS
    tink::signature::subtle::composite_ml_dsa_sign_boringssl
    tink::signature::subtle::composite_ml_dsa_verify_boringssl
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::low_level_crypto_access
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_util
    tink::signature::internal::testing::composite_ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
    tink::util::test_matchers
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME create_ecdsa_key
  SRCS
    create_ecdsa_key.cc
    create_ecdsa_key.h
  DEPS
    absl::statusor
    tink::signature::ecdsa_parameters
    tink::signature::ecdsa_private_key
    tink::signature::internal::ecdsa_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_ecdsa_key_test
  SRCS
    create_ecdsa_key_test.cc
  DEPS
    tink::signature::subtle::create_ecdsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::signature::ecdsa_parameters
    tink::signature::ecdsa_private_key
)

tink_cc_library(
  NAME create_ed25519_key
  SRCS
    create_ed25519_key.cc
    create_ed25519_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::ed25519_parameters
    tink::signature::ed25519_private_key
    tink::signature::internal::ed25519_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_ed25519_key_test
  SRCS
    create_ed25519_key_test.cc
  DEPS
    tink::signature::subtle::create_ed25519_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::signature::ed25519_parameters
    tink::signature::ed25519_private_key
)

tink_cc_library(
  NAME create_rsa_ssa_pkcs1_key
  SRCS
    create_rsa_ssa_pkcs1_key.cc
    create_rsa_ssa_pkcs1_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::rsa_ssa_pkcs1_parameters
    tink::signature::rsa_ssa_pkcs1_private_key
    tink::signature::internal::rsa_ssa_pkcs1_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_rsa_ssa_pkcs1_key_test
  SRCS
    create_rsa_ssa_pkcs1_key_test.cc
  DEPS
    tink::signature::subtle::create_rsa_ssa_pkcs1_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::signature::rsa_ssa_pkcs1_parameters
    tink::signature::rsa_ssa_pkcs1_private_key
)

tink_cc_library(
  NAME create_rsa_ssa_pss_key
  SRCS
    create_rsa_ssa_pss_key.cc
    create_rsa_ssa_pss_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::rsa_ssa_pss_parameters
    tink::signature::rsa_ssa_pss_private_key
    tink::signature::internal::rsa_ssa_pss_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_rsa_ssa_pss_key_test
  SRCS
    create_rsa_ssa_pss_key_test.cc
  DEPS
    tink::signature::subtle::create_rsa_ssa_pss_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::signature::rsa_ssa_pss_parameters
    tink::signature::rsa_ssa_pss_private_key
)

tink_cc_library(
  NAME create_ml_dsa_key
  SRCS
    create_ml_dsa_key.cc
    create_ml_dsa_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::ml_dsa_parameters
    tink::signature::ml_dsa_private_key
    tink::signature::internal::ml_dsa_key_creator
  PUBLIC
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME create_ml_dsa_key_test
  SRCS
    create_ml_dsa_key_test.cc
  DEPS
    tink::signature::subtle::create_ml_dsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::signature::ml_dsa_parameters
    tink::signature::ml_dsa_private_key
  TAGS
    exclude_if_openssl
)

