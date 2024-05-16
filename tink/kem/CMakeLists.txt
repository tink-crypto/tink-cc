tink_cc_library(
  NAME kem_decapsulate
  SRCS
    kem_decapsulate.h
  DEPS
    absl::strings
    tink::core::keyset_handle
    tink::util::statusor
)

tink_cc_library(
  NAME kem_encapsulate
  SRCS
    kem_encapsulate.h
  DEPS
    tink::core::keyset_handle
    tink::util::statusor
)
