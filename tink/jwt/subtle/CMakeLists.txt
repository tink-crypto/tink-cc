tink_module(jwt::subtle)

tink_cc_library(
  NAME create_jwt_ml_dsa_key
  SRCS
    create_jwt_ml_dsa_key.cc
    create_jwt_ml_dsa_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::jwt::jwt_ml_dsa_parameters
    tink::jwt::jwt_ml_dsa_private_key
    tink::jwt::internal::jwt_ml_dsa_key_creator
  PUBLIC
  TAGS
    exclude_if_openssl
)

tink_cc_test(
  NAME create_jwt_ml_dsa_key_test
  SRCS
    create_jwt_ml_dsa_key_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_ml_dsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_ml_dsa_parameters
    tink::jwt::jwt_ml_dsa_private_key
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME create_jwt_ecdsa_key
  SRCS
    create_jwt_ecdsa_key.cc
    create_jwt_ecdsa_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::internal::jwt_ecdsa_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_ecdsa_key_test
  SRCS
    create_jwt_ecdsa_key_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_ecdsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
)

tink_cc_library(
  NAME create_jwt_rsa_ssa_pss_key
  SRCS
    create_jwt_rsa_ssa_pss_key.cc
    create_jwt_rsa_ssa_pss_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
    tink::jwt::internal::jwt_rsa_ssa_pss_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_rsa_ssa_pss_key_test
  SRCS
    create_jwt_rsa_ssa_pss_key_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_rsa_ssa_pss_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_rsa_ssa_pss_parameters
    tink::jwt::jwt_rsa_ssa_pss_private_key
)

tink_cc_library(
  NAME create_jwt_rsa_ssa_pkcs1_key
  SRCS
    create_jwt_rsa_ssa_pkcs1_key.cc
    create_jwt_rsa_ssa_pkcs1_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
    tink::jwt::internal::jwt_rsa_ssa_pkcs1_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_rsa_ssa_pkcs1_key_test
  SRCS
    create_jwt_rsa_ssa_pkcs1_key_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_rsa_ssa_pkcs1_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_rsa_ssa_pkcs1_parameters
    tink::jwt::jwt_rsa_ssa_pkcs1_private_key
)

tink_cc_library(
  NAME create_jwt_hmac_key
  SRCS
    create_jwt_hmac_key.cc
    create_jwt_hmac_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    tink::jwt::internal::jwt_mac_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_hmac_key_test
  SRCS
    create_jwt_hmac_key_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_hmac_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
)
