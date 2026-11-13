cmake_minimum_required(VERSION 3.22)

project(Examples CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Import Tink as an in-tree dependency.
set(TINK_BUILD_TESTS OFF)
set(TINK_BUILD_TESTONLY ON)
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
endif()

enable_testing()

add_subdirectory(util)
add_subdirectory(aead)
add_subdirectory(daead)
add_subdirectory(digital_signatures)
add_subdirectory(hybrid_encryption)
add_subdirectory(jwt)
add_subdirectory(key_derivation)
add_subdirectory(mac)
add_subdirectory(walkthrough)
