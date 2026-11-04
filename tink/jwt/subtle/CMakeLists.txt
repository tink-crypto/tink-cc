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

tink_cc_library(
  NAME create_jwt_hmac
  SRCS
    create_jwt_hmac.cc
    create_jwt_hmac.h
  DEPS
    absl::statusor
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_mac
    tink::jwt::internal::jwt_hmac
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_hmac_test
  SRCS
    create_jwt_hmac_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_hmac
    gmock
    absl::status_matchers
    absl::statusor
    tink::core::partial_key_access
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
    tink::jwt::jwt_mac
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::jwt::internal::testing::jwt_hmac_test_vectors
)

tink_cc_library(
  NAME create_jwt_ecdsa_public_key_sign
  SRCS
    create_jwt_ecdsa_public_key_sign.cc
    create_jwt_ecdsa_public_key_sign.h
  DEPS
    absl::statusor
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_public_key_sign
    tink::jwt::internal::jwt_ecdsa_sign
  PUBLIC
)

tink_cc_test(
  NAME create_jwt_ecdsa_public_key_sign_test
  SRCS
    create_jwt_ecdsa_public_key_sign_test.cc
  DEPS
    tink::jwt::subtle::create_jwt_ecdsa_public_key_sign
    gmock
    absl::status_matchers
    absl::statusor
    tink::jwt::jwt_public_key_sign
    tink::jwt::jwt_public_key_verify
    tink::jwt::jwt_validator
    tink::jwt::raw_jwt
    tink::jwt::verified_jwt
    tink::jwt::internal::jwt_ecdsa_verify
    tink::jwt::internal::testing::jwt_ecdsa_test_vectors
)
