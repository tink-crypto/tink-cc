tink_cc_library(
  NAME kem_parameters
  SRCS
    kem_parameters.h
  DEPS
    tink::core::parameters
)

tink_cc_library(
  NAME kem_private_key
  SRCS
    kem_private_key.h
  DEPS
    tink::experimental::kem::kem_parameters
    tink::experimental::kem::kem_public_key
    absl::string_view
    absl::optional
    tink::core::key
    tink::core::private_key
)

tink_cc_library(
  NAME kem_public_key
  SRCS
    kem_public_key.h
  DEPS
    tink::experimental::kem::kem_parameters
    absl::string_view
    tink::core::key
)
