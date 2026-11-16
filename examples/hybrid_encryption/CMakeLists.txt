add_executable(hybrid_cli hybrid_cli.cc)
target_include_directories(hybrid_cli PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(hybrid_cli
  tink::tink
  absl::absl_check
  absl::flags_parse
  util)

add_test(
  NAME hybrid_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/hybrid_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/hybrid_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hybrid_test_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hybrid_test_public_keyset.json")

add_test(
  NAME hpke_cli_test
  COMMAND "${BASH_PROGRAM}"
    "${CMAKE_CURRENT_SOURCE_DIR}/hybrid_cli_test.sh"
    "${CMAKE_CURRENT_BINARY_DIR}/hybrid_cli"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hpke_test_private_keyset.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/testdata/hpke_test_public_keyset.json")
