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
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::status
    absl::statusor
    absl::string_view
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::hybrid::hpke_parameters
    tink::hybrid::hpke_private_key
    tink::hybrid::hpke_public_key
    tink::internal::mlkem_util
    tink::subtle::common_enums
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
    absl::no_destructor
    absl::flat_hash_map
    absl::absl_check
    absl::statusor
    absl::optional
    tink::core::insecure_secret_key_access
    tink::core::partial_key_access
    tink::core::restricted_data
    tink::hybrid::ecies_parameters
    tink::hybrid::ecies_private_key
    tink::hybrid::ecies_public_key
    tink::hybrid::hybrid_private_key
    tink::internal::testing::ec_test_vectors
    tink::subtle::common_enums
    tink::util::test_util
  TESTONLY
)

tink_cc_library(
  NAME ecies_test_util
  SRCS
    ecies_test_util.cc
    ecies_test_util.h
  DEPS
    absl::absl_check
    absl::statusor
    tink::aead::aes_ctr_hmac_aead_key_manager
    tink::aead::aes_gcm_key_manager
    tink::aead::xchacha20_poly1305_key_manager
    tink::daead::aes_siv_key_manager
    tink::internal::ec_util
    tink::subtle::common_enums
    tink::util::enums
    tink::util::secret_data
    tink::proto::aes_ctr_cc_proto
    tink::proto::aes_ctr_hmac_aead_cc_proto
    tink::proto::aes_gcm_cc_proto
    tink::proto::aes_siv_cc_proto
    tink::proto::common_cc_proto
    tink::proto::ecies_aead_hkdf_cc_proto
    tink::proto::hmac_cc_proto
    tink::proto::xchacha20_poly1305_cc_proto
  TESTONLY
)

