# Library targets.

add_library(create_keyset create_keyset.cc create_keyset.h)
target_include_directories(create_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(create_keyset
  PUBLIC
    absl::statusor
    tink::tink
)

add_library(load_cleartext_keyset load_cleartext_keyset.cc load_cleartext_keyset.h)
target_include_directories(load_cleartext_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(load_cleartext_keyset
  PUBLIC
    absl::statusor
    absl::strings
    tink::tink
)

add_library(test_util test_util.cc test_util.h)
target_include_directories(test_util PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(test_util
  PUBLIC
    absl::statusor
    absl::strings
    tink::tink
  PRIVATE
    load_cleartext_keyset
    absl::status
)

add_library(load_encrypted_keyset load_encrypted_keyset.cc load_encrypted_keyset.h)
target_include_directories(load_encrypted_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(load_encrypted_keyset
  PUBLIC
    absl::statusor
    absl::strings
    tink::tink
)

add_library(write_keyset write_keyset.cc write_keyset.h)
target_include_directories(write_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(write_keyset
  PUBLIC
    absl::status
    tink::tink
  PRIVATE
    absl::statusor
)

add_library(obtain_and_use_a_primitive obtain_and_use_a_primitive.cc obtain_and_use_a_primitive.h)
target_include_directories(obtain_and_use_a_primitive PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(obtain_and_use_a_primitive
  PUBLIC
    absl::statusor
    absl::strings
    tink::tink
)

add_library(write_cleartext_keyset write_cleartext_keyset.cc write_cleartext_keyset.h)
target_include_directories(write_cleartext_keyset PUBLIC "${TINK_EXAMPLES_INCLUDE_PATH}")
target_link_libraries(write_cleartext_keyset
  PUBLIC
    absl::status
    tink::tink
  PRIVATE
    absl::statusor
)

# Test targets.

add_executable(create_keyset_test create_keyset_test.cc)
add_test(NAME create_keyset_test COMMAND create_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(create_keyset_test
  PRIVATE
    create_keyset
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
    GTest::gmock
    GTest::gtest_main
)

add_executable(load_cleartext_keyset_test load_cleartext_keyset_test.cc)
add_test(NAME load_cleartext_keyset_test COMMAND load_cleartext_keyset_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(load_cleartext_keyset_test
  PRIVATE
    load_cleartext_keyset
    absl::status
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
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
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
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
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
    GTest::gmock
    GTest::gtest_main
)

add_executable(obtain_and_use_a_primitive_test obtain_and_use_a_primitive_test.cc)
add_test(NAME obtain_and_use_a_primitive_test COMMAND obtain_and_use_a_primitive_test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
target_link_libraries(obtain_and_use_a_primitive_test
  PRIVATE
    load_cleartext_keyset
    obtain_and_use_a_primitive
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
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
    absl::status_matchers
    absl::statusor
    absl::strings
    tink::testonly
    GTest::gmock
    GTest::gtest_main
)
