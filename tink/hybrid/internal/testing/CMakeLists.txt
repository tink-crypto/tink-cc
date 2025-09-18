tink_module(hybrid::internal::testing)

tink_cc_library(
  NAME hybrid_test_vectors
  SRCS
    hybrid_test_vectors.h
  DEPS
    absl::string_view
    tink::hybrid::hybrid_private_key
  TESTONLY
)

tink_cc_library(
  NAME hpke_test_vectors
  SRCS
    hpke_test_vectors.cc
    hpke_test_vectors.h
  DEPS
    tink::hybrid::internal::testing::hybrid_test_vectors
    absl::check
    absl::statusor
    absl::strings
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::core::secret_data
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    tink::util::secret_data
    tink::util::test_util
  TESTONLY
  TAGS
    exclude_if_openssl
)

tink_cc_library(
  NAME ecies_aead_hkdf_test_vectors
  SRCS
    ecies_aead_hkdf_test_vectors.cc
    ecies_aead_hkdf_test_vectors.h
  DEPS
    tink::hybrid::internal::testing::hybrid_test_vectors
    absl::check
    absl::optional
    tink::core::big_integer
    tink::core::ec_point
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_big_integer
    tink::core::restricted_data
    tink::hybrid::ecies_parameters
    tink::hybrid::ecies_private_key
    tink::hybrid::ecies_public_key
    tink::util::statusor
    tink::util::test_util
  TESTONLY
)
