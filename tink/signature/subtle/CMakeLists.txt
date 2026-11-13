tink_module(signature::subtle)

tink_cc_library(
  NAME composite_ml_dsa_sign_boringssl
  SRCS
    composite_ml_dsa_sign_boringssl.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::composite_ml_dsa_sign_boringssl
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
    tink::core::public_key_sign
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_util
    tink::util::test_matchers
)

tink_cc_library(
  NAME composite_ml_dsa_verify_boringssl
  SRCS
    composite_ml_dsa_verify_boringssl.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::composite_ml_dsa_public_key
    tink::signature::internal::composite_ml_dsa_verify_boringssl
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
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_util
    tink::signature::internal::testing::composite_ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
    tink::util::test_matchers
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
)

tink_cc_library(
  NAME create_composite_ml_dsa_key
  SRCS
    create_composite_ml_dsa_key.cc
    create_composite_ml_dsa_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::composite_ml_dsa_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_composite_ml_dsa_key_test
  SRCS
    create_composite_ml_dsa_key_test.cc
  DEPS
    tink::signature::subtle::create_composite_ml_dsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
)

tink_cc_library(
  NAME create_slh_dsa_key
  SRCS
    create_slh_dsa_key.cc
    create_slh_dsa_key.h
  DEPS
    absl::status_macros
    absl::statusor
    tink::signature::slh_dsa_parameters
    tink::signature::slh_dsa_private_key
    tink::signature::internal::slh_dsa_key_creator
  PUBLIC
)

tink_cc_test(
  NAME create_slh_dsa_key_test
  SRCS
    create_slh_dsa_key_test.cc
  DEPS
    tink::signature::subtle::create_slh_dsa_key
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::signature::slh_dsa_parameters
    tink::signature::slh_dsa_private_key
)

tink_cc_library(
  NAME create_ml_dsa_signer
  SRCS
    create_ml_dsa_signer.cc
    create_ml_dsa_signer.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::ml_dsa_private_key
    tink::signature::internal::ml_dsa_sign_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ml_dsa_signer_test
  SRCS
    create_ml_dsa_signer_test.cc
  DEPS
    tink::signature::subtle::create_ml_dsa_signer
    tink::signature::subtle::create_ml_dsa_verifier
    gmock
    absl::status_matchers
    absl::statusor
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ml_dsa_private_key
    tink::signature::internal::testing::ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ml_dsa_verifier
  SRCS
    create_ml_dsa_verifier.cc
    create_ml_dsa_verifier.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::ml_dsa_public_key
    tink::signature::internal::ml_dsa_verify_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ml_dsa_verifier_test
  SRCS
    create_ml_dsa_verifier_test.cc
  DEPS
    tink::signature::subtle::create_ml_dsa_signer
    tink::signature::subtle::create_ml_dsa_verifier
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ml_dsa_parameters
    tink::signature::ml_dsa_private_key
    tink::signature::internal::testing::ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_slh_dsa_verifier
  SRCS
    create_slh_dsa_verifier.cc
    create_slh_dsa_verifier.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::slh_dsa_public_key
    tink::signature::internal::slh_dsa_verify_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_slh_dsa_verifier_test
  SRCS
    create_slh_dsa_verifier_test.cc
  DEPS
    tink::signature::subtle::create_slh_dsa_verifier
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::slh_dsa_parameters
    tink::signature::slh_dsa_private_key
    tink::signature::internal::testing::signature_test_vector
    tink::signature::internal::testing::slh_dsa_test_vectors
)

tink_cc_library(
  NAME create_slh_dsa_signer
  SRCS
    create_slh_dsa_signer.cc
    create_slh_dsa_signer.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::slh_dsa_private_key
    tink::signature::internal::slh_dsa_sign_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_slh_dsa_signer_test
  SRCS
    create_slh_dsa_signer_test.cc
  DEPS
    tink::signature::subtle::create_slh_dsa_signer
    tink::signature::subtle::create_slh_dsa_verifier
    gmock
    absl::status_matchers
    absl::statusor
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::slh_dsa_private_key
    tink::signature::internal::testing::signature_test_vector
    tink::signature::internal::testing::slh_dsa_test_vectors
)

tink_cc_library(
  NAME create_ml_dsa_prehash
  SRCS
    create_ml_dsa_prehash.cc
    create_ml_dsa_prehash.h
  DEPS
    absl::statusor
    tink::signature::ml_dsa_public_key
    tink::signature::prehash
    tink::signature::internal::ml_dsa_prehash_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ml_dsa_prehash_test
  SRCS
    create_ml_dsa_prehash_test.cc
  DEPS
    tink::signature::subtle::create_ml_dsa_prehash
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::internal::boringssl
    tink::internal::fips_utils
    tink::signature::ml_dsa_parameters
    tink::signature::ml_dsa_private_key
    tink::signature::prehash
    tink::signature::internal::testing::ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ml_dsa_sign_prehash
  SRCS
    create_ml_dsa_sign_prehash.cc
    create_ml_dsa_sign_prehash.h
  DEPS
    absl::statusor
    tink::signature::ml_dsa_private_key
    tink::signature::sign_prehash
    tink::signature::internal::ml_dsa_sign_prehash_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ml_dsa_sign_prehash_test
  SRCS
    create_ml_dsa_sign_prehash_test.cc
  DEPS
    tink::signature::subtle::create_ml_dsa_sign_prehash
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ml_dsa_parameters
    tink::signature::ml_dsa_private_key
    tink::signature::sign_prehash
    tink::signature::internal::ml_dsa_verify_boringssl
    tink::signature::internal::testing::ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_composite_ml_dsa_verifier
  SRCS
    create_composite_ml_dsa_verifier.cc
    create_composite_ml_dsa_verifier.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::composite_ml_dsa_public_key
    tink::signature::internal::composite_ml_dsa_verify_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_composite_ml_dsa_verifier_test
  SRCS
    create_composite_ml_dsa_verifier_test.cc
  DEPS
    tink::signature::subtle::create_composite_ml_dsa_verifier
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_parameters
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_composite_ml_dsa_signer
  SRCS
    create_composite_ml_dsa_signer.cc
    create_composite_ml_dsa_signer.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::composite_ml_dsa_sign_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_composite_ml_dsa_signer_test
  SRCS
    create_composite_ml_dsa_signer_test.cc
  DEPS
    tink::signature::subtle::create_composite_ml_dsa_signer
    tink::signature::subtle::create_composite_ml_dsa_verifier
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::composite_ml_dsa_private_key
    tink::signature::internal::testing::composite_ml_dsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ecdsa_signer
  SRCS
    create_ecdsa_signer.cc
    create_ecdsa_signer.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::ecdsa_private_key
    tink::signature::internal::ecdsa_sign_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ecdsa_signer_test
  SRCS
    create_ecdsa_signer_test.cc
  DEPS
    tink::signature::subtle::create_ecdsa_signer
    tink::signature::subtle::create_ecdsa_verifier
    gmock
    absl::status_matchers
    absl::statusor
    tink::core::public_key_sign
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ecdsa_private_key
    tink::signature::internal::testing::ecdsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ecdsa_verifier
  SRCS
    create_ecdsa_verifier.cc
    create_ecdsa_verifier.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::ecdsa_public_key
    tink::signature::internal::ecdsa_verify_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ecdsa_verifier_test
  SRCS
    create_ecdsa_verifier_test.cc
  DEPS
    tink::signature::subtle::create_ecdsa_verifier
    gmock
    absl::status
    absl::status_matchers
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ecdsa_private_key
    tink::signature::internal::testing::ecdsa_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ed25519_signer
  SRCS
    create_ed25519_signer.cc
    create_ed25519_signer.h
  DEPS
    absl::statusor
    tink::core::public_key_sign
    tink::signature::ed25519_private_key
    tink::signature::internal::ed25519_sign_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ed25519_signer_test
  SRCS
    create_ed25519_signer_test.cc
  DEPS
    tink::signature::subtle::create_ed25519_signer
    gmock
    absl::status_matchers
    absl::statusor
    tink::core::public_key_sign
    tink::internal::fips_utils
    tink::signature::ed25519_private_key
    tink::signature::internal::testing::ed25519_test_vectors
    tink::signature::internal::testing::signature_test_vector
)

tink_cc_library(
  NAME create_ed25519_verifier
  SRCS
    create_ed25519_verifier.cc
    create_ed25519_verifier.h
  DEPS
    absl::statusor
    tink::core::public_key_verify
    tink::signature::ed25519_public_key
    tink::signature::internal::ed25519_verify_boringssl
  PUBLIC
)

tink_cc_test(
  NAME create_ed25519_verifier_test
  SRCS
    create_ed25519_verifier_test.cc
  DEPS
    tink::signature::subtle::create_ed25519_verifier
    gmock
    absl::status_matchers
    absl::statusor
    absl::strings
    absl::string_view
    tink::core::public_key_verify
    tink::internal::fips_utils
    tink::signature::ed25519_private_key
    tink::signature::internal::testing::ed25519_test_vectors
    tink::signature::internal::testing::signature_test_vector
)
