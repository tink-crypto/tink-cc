cmake_minimum_required(VERSION 3.13)

project(Examples CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Release)

# Import Tink as an in-tree dependency.
set(TINK_BUILD_TESTS OFF)
add_subdirectory(.. tink)

# Make sure we have bash.
find_program(BASH_PROGRAM bash REQUIRED)

# Include path at the base of the examples folder.
set(TINK_EXAMPLES_INCLUDE_PATH "${CMAKE_SOURCE_DIR}")

if (TINK_USE_INSTALLED_ABSEIL)
  find_package(absl REQUIRED)
endif()

if (TINK_USE_INSTALLED_GOOGLETEST)
  find_package(GTest CONFIG REQUIRED)
  # NOTE: _create_interface_target is inherited by Tink.
  _create_interface_target(gmock GTest::gmock)
  _create_interface_target(gtest_main GTest::gtest_main)
else()
  include(FetchContent)

  FetchContent_Declare(
    googletest
    URL       https://github.com/google/googletest/releases/download/v1.15.2/googletest-1.15.2.tar.gz
    URL_HASH  SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
  )

  FetchContent_GetProperties(googletest)
  if(NOT googletest_POPULATED)
    FetchContent_Populate(googletest)
    add_subdirectory(
      ${googletest_SOURCE_DIR}
      ${googletest_BINARY_DIR})
  endif()
endif()

enable_testing()

add_subdirectory(util)
add_subdirectory(aead)
add_subdirectory(digital_signatures)
add_subdirectory(hybrid_encryption)
add_subdirectory(jwt)
add_subdirectory(mac)
add_subdirectory(walkthrough)
