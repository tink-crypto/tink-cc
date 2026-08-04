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
    absl::strings
  TESTONLY
)

