tink_module(jwt::internal::testing)

tink_cc_library(
  NAME jwt_rsa_ssa_test_vectors
  SRCS
    jwt_rsa_ssa_test_vectors.cc
    jwt_rsa_ssa_test_vectors.h
  DEPS
    absl::no_destructor
    absl::absl_check
    absl::strings
  TESTONLY
)

tink_cc_library(
  NAME jwt_hmac_test_vectors
  SRCS
    jwt_hmac_test_vectors.cc
    jwt_hmac_test_vectors.h
  DEPS
    absl::core_headers
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::strings
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::jwt::jwt_hmac_key
    tink::jwt::jwt_hmac_parameters
  TESTONLY
)

tink_cc_library(
  NAME jwt_ecdsa_test_vectors
  SRCS
    jwt_ecdsa_test_vectors.cc
    jwt_ecdsa_test_vectors.h
  DEPS
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::string_view
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::jwt::jwt_ecdsa_parameters
    tink::jwt::jwt_ecdsa_private_key
    tink::jwt::jwt_ecdsa_public_key
    tink::subtle::common_enums
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME jwt_ml_dsa_test_vectors
  SRCS
    jwt_ml_dsa_test_vectors.cc
    jwt_ml_dsa_test_vectors.h
  DEPS
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::string_view
    tink::jwt::jwt_ml_dsa_parameters
    tink::util::test_util
  TESTONLY
)

