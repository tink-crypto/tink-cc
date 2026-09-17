# Library targets.

add_library(create_keyset create_keyset.cc create_keyset.h)
target_include_directories(create_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(create_keyset
  PUBLIC
    absl::statusor
    tink::core::keyset_handle
    tink::util::statusor
  PRIVATE
    tink::aead::aead_key_templates
    tink::config::global_registry
    tink::proto::tink_cc_proto
)

add_library(load_cleartext_keyset load_cleartext_keyset.cc load_cleartext_keyset.h)
target_include_directories(load_cleartext_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(load_cleartext_keyset
  PUBLIC
    absl::statusor
    absl::strings
    tink::core::keyset_handle
    tink::util::statusor
  PRIVATE
    tink::core::cleartext_keyset_handle
    tink::core::keyset_reader
    tink::json::json_keyset_reader
)

add_library(test_util test_util.cc test_util.h)
target_include_directories(test_util PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(test_util
  PUBLIC
    absl::statusor
    absl::strings
    tink::core::aead
    tink::core::kms_client
    tink::util::statusor
  PRIVATE
    load_cleartext_keyset
    absl::status
    tink::config::global_registry
    tink::core::keyset_handle
)

add_library(load_encrypted_keyset load_encrypted_keyset.cc load_encrypted_keyset.h)
target_include_directories(load_encrypted_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(load_encrypted_keyset
  PUBLIC
    absl::statusor
    absl::strings
    tink::core::aead
    tink::core::keyset_handle
    tink::util::statusor
  PRIVATE
    tink::core::keyset_reader
    tink::json::json_keyset_reader
)

add_library(write_keyset write_keyset.cc write_keyset.h)
target_include_directories(write_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(write_keyset
  PUBLIC
    absl::status
    tink::core::aead
    tink::core::keyset_handle
    tink::util::status
  PRIVATE
    absl::statusor
    tink::json::json_keyset_writer
)

add_library(obtain_and_use_a_primitive obtain_and_use_a_primitive.cc obtain_and_use_a_primitive.h)
target_include_directories(obtain_and_use_a_primitive PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(obtain_and_use_a_primitive
  PUBLIC
    absl::statusor
    absl::strings
    tink::core::keyset_handle
    tink::util::statusor
  PRIVATE
    tink::config::global_registry
    tink::core::aead
)

add_library(write_cleartext_keyset write_cleartext_keyset.cc write_cleartext_keyset.h)
target_include_directories(write_cleartext_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(write_cleartext_keyset
  PUBLIC
    absl::status
    tink::core::keyset_handle
  PRIVATE
    absl::statusor
    tink::core::cleartext_keyset_handle
    tink::json::json_keyset_writer
    tink::util::status
)

# Test targets.

add_executable(create_keyset_test create_keyset_test.cc)
add_test(NAME create_keyset_test COMMAND create_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(create_keyset_test
  PRIVATE
    create_keyset
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::config::global_registry
    tink::core::aead
    tink::core::keyset_handle
    tink::core::registry
    GTest::gmock
    GTest::gtest_main
)

add_executable(load_cleartext_keyset_test load_cleartext_keyset_test.cc)
add_test(NAME load_cleartext_keyset_test COMMAND load_cleartext_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(load_cleartext_keyset_test
  PRIVATE
    load_cleartext_keyset
    absl::status
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::config::global_registry
    tink::core::aead
    tink::core::keyset_handle
    GTest::gmock
    GTest::gtest_main
)

add_executable(load_encrypted_keyset_test load_encrypted_keyset_test.cc)
add_test(NAME load_encrypted_keyset_test COMMAND load_encrypted_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(load_encrypted_keyset_test
  PRIVATE
    load_cleartext_keyset
    load_encrypted_keyset
    test_util
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::config::global_registry
    tink::core::aead
    tink::core::keyset_handle
    tink::core::kms_clients
    tink::core::registry
    GTest::gmock
    GTest::gtest_main
)

add_executable(write_keyset_test write_keyset_test.cc)
add_test(NAME write_keyset_test COMMAND write_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(write_keyset_test
  PRIVATE
    load_cleartext_keyset
    load_encrypted_keyset
    test_util
    write_keyset
    absl::memory
    absl::status
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::config::global_registry
    tink::core::aead
    tink::core::keyset_handle
    tink::core::kms_clients
    GTest::gmock
    GTest::gtest_main
)

add_executable(obtain_and_use_a_primitive_test obtain_and_use_a_primitive_test.cc)
add_test(NAME obtain_and_use_a_primitive_test COMMAND obtain_and_use_a_primitive_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(obtain_and_use_a_primitive_test
  PRIVATE
    load_cleartext_keyset
    obtain_and_use_a_primitive
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::core::keyset_handle
    GTest::gmock
    GTest::gtest_main
)

add_executable(write_cleartext_keyset_test write_cleartext_keyset_test.cc)
add_test(NAME write_cleartext_keyset_test COMMAND write_cleartext_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(write_cleartext_keyset_test
  PRIVATE
    load_cleartext_keyset
    write_cleartext_keyset
    absl::memory
    absl::statusor
    absl::strings
    tink::aead::aead_config
    tink::config::global_registry
    tink::core::aead
    tink::core::keyset_handle
    GTest::gmock
    GTest::gtest_main
)
