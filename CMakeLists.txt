cmake_minimum_required(VERSION 3.22)

project(Tink VERSION 2.9.2 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)
option(TINK_USE_INSTALLED_ABSEIL "Build Tink linking to Abseil installed in the system" OFF)
option(TINK_USE_INSTALLED_GOOGLETEST "Build Tink linking to GTest installed in the system" OFF)
option(TINK_USE_INSTALLED_PROTOBUF "Build Tink linking to Protobuf installed in the system" OFF)
option(TINK_USE_INSTALLED_BENCHMARK "Build Tink linking to benchmark installed in the system" OFF)
option(USE_ONLY_FIPS "Enables the FIPS only mode in Tink" OFF)

set(CPACK_GENERATOR TGZ)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

# For MSCV, force the static runtime.
# Currently, both absl and cmake allow to override this. In order to make things
# more likely to be built correctly we currently only allow static runtimes.
# We need to do this before "include(TinkWorkspace)" since we need to do it
# before loading absl/proto.
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(ABSL_MSVC_STATIC_RUNTIME ON)
  set(protobuf_MSVC_STATIC_RUNTIME ON)
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>)
endif()

if (TINK_BUILD_TESTS)
  # We do not want to test Abseil
  set(ABSL_BUILD_TESTING OFF CACHE BOOL "" FORCE)
  # We do build the Abseil test helpers though -- we use them.
  set(ABSL_BUILD_TEST_HELPERS ON CACHE BOOL "" FORCE)
  # Tink needs Googletest, so Abseil is never responsible for installing it.
  set(ABSL_USE_EXTERNAL_GOOGLETEST ON CACHE BOOL "" FORCE)
  # If Tink uses an installed GTest, Abseil should use that one too.
  if (TINK_USE_INSTALLED_GOOGLETEST)
    set(ABSL_FIND_GOOGLETEST ON CACHE BOOL "" FORCE)
  else()
    set(ABSL_FIND_GOOGLETEST OFF CACHE BOOL "" FORCE)
  endif()
endif()

include(CPack)
include(TinkWorkspace)
include(TinkBuildRules)

# BoringSSL only applies BORINGSSL_PREFIX to its own targets (add_definitions is
# directory-scoped). Tink's sources include BoringSSL headers, so they must be
# compiled with the same BORINGSSL_PREFIX as the BoringSSL they link against.
# This is directory-scoped too: it applies to Tink's targets only, not to
# projects that consume Tink.
if (BORINGSSL_PREFIX)
  add_compile_definitions(BORINGSSL_PREFIX=${BORINGSSL_PREFIX})
endif()

list(APPEND TINK_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(tink)
add_subdirectory(proto)
