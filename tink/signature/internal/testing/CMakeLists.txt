tink_module(signature::internal::testing)

tink_cc_library(
  NAME rsa_ssa_pkcs1_test_vectors
  SRCS
    rsa_ssa_pkcs1_test_vectors.cc
    rsa_ssa_pkcs1_test_vectors.h
  DEPS
    tink::signature::internal::testing::signature_test_vector
    absl::check
    absl::memory
    absl::strings
    absl::optional
    tink::core::big_integer
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::signature::rsa_ssa_pkcs1_parameters
    tink::signature::rsa_ssa_pkcs1_private_key
    tink::signature::rsa_ssa_pkcs1_public_key
    tink::util::statusor
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME signature_test_vector
  SRCS
    signature_test_vector.h
  DEPS
    absl::string_view
    tink::signature::signature_private_key
  TESTONLY
)
