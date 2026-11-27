tink_module(kem)

add_subdirectory(internal)

tink_cc_library(
  NAME kem_decapsulate
  SRCS
    kem_decapsulate.h
  DEPS
    absl::strings
    tink::core::keyset_handle
    tink::core::rtti
    tink::util::statusor
)

tink_cc_library(
  NAME kem_encapsulate
  SRCS
    kem_encapsulate.h
  DEPS
    tink::core::keyset_handle
    tink::core::rtti
    tink::util::statusor
)
