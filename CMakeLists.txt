cmake_minimum_required(VERSION 3.22)

project(Tink VERSION 2.9.2 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)
option(TINK_BUILD_TESTONLY "Build Tink testonly targets" OFF)
if (TINK_BUILD_TESTS)
  set(TINK_BUILD_TESTONLY ON)
endif()
option(TINK_USE_INSTALLED_ABSEIL "Build Tink linking to Abseil installed in the system" OFF)
option(TINK_USE_INSTALLED_GOOGLETEST "Build Tink linking to GTest installed in the system" OFF)
option(TINK_USE_INSTALLED_PROTOBUF "Build Tink linking to Protobuf installed in the system" OFF)
option(TINK_USE_INSTALLED_BENCHMARK "Build Tink linking to benchmark installed in the system" OFF)

# Announce BUILD_SHARED_LIBS where supported.
if(NOT MSVC)
  option(BUILD_SHARED_LIBS "Build shared libraries instead of static ones" OFF)
endif()

# When building as a shared library, force PIC, as some subcomponents are
# statically linked into them.
if(BUILD_SHARED_LIBS)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# For MSVC, force the static runtime.
# Currently, both absl and cmake allow to override this. In order to make things
# more likely to be built correctly we currently only allow static runtimes.
# We need to do this before "include(TinkWorkspace)" since we need to do it
# before loading absl/proto.
if(MSVC)
  set(ABSL_MSVC_STATIC_RUNTIME ON)
  set(protobuf_MSVC_STATIC_RUNTIME ON)
  set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded$<$<CONFIG:Debug>:Debug>)
  if(BUILD_SHARED_LIBS)
    # To support shared libraries on MSVC, one first has to implement proper
    # dllexport/dllimport handling. Elsewhere, visibility does the trick.
    message(FATAL_ERROR "Shared libraries are not supported with MSVC.")
  endif()
endif()

# Allow the linker to deduplicate libraries. Removes warnings on macOS.
set(CMAKE_LINK_LIBRARIES_STRATEGY REORDER_FREELY)

set(_tink_enable_install_default OFF)
if (PROJECT_IS_TOP_LEVEL
    AND TINK_USE_INSTALLED_ABSEIL
    AND TINK_USE_INSTALLED_PROTOBUF
    AND (NOT TINK_BUILD_TESTONLY OR TINK_USE_INSTALLED_GOOGLETEST))
  set(_tink_enable_install_default ON)
endif()
option(TINK_ENABLE_INSTALL
  "Enable installation and package export of Tink"
  ${_tink_enable_install_default})
unset(_tink_enable_install_default)

if (TINK_ENABLE_INSTALL)
  if (NOT TINK_USE_INSTALLED_ABSEIL)
    message(FATAL_ERROR
      "TINK_ENABLE_INSTALL requires TINK_USE_INSTALLED_ABSEIL=ON")
  endif()
  if (NOT TINK_USE_INSTALLED_PROTOBUF)
    message(FATAL_ERROR
      "TINK_ENABLE_INSTALL requires TINK_USE_INSTALLED_PROTOBUF=ON")
  endif()
  if (TINK_BUILD_TESTONLY AND NOT TINK_USE_INSTALLED_GOOGLETEST)
    message(FATAL_ERROR
      "TINK_ENABLE_INSTALL with TINK_BUILD_TESTONLY requires TINK_USE_INSTALLED_GOOGLETEST=ON")
  endif()
endif()

if (TINK_BUILD_TESTONLY)
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

include(TinkWorkspace)
include(TinkBuildRules)

# BoringSSL only applies BORINGSSL_PREFIX and OPENSSL_NO_SOCK to its own targets
# (directory-scoped). Tink's sources include BoringSSL headers, so they must be
# compiled with the matching defines. This is directory-scoped too: it applies
# to Tink's targets only, not to projects that consume Tink.
add_compile_definitions(BORINGSSL_PREFIX=${BORINGSSL_PREFIX} OPENSSL_NO_SOCK=)

list(APPEND TINK_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(tink)
add_subdirectory(proto)

if (PROJECT_IS_TOP_LEVEL AND NOT TINK_ENABLE_INSTALL)
  install(CODE [[message(FATAL_ERROR
    "Installing Tink requires TINK_ENABLE_INSTALL=ON "
    "(with TINK_USE_INSTALLED_ABSEIL=ON, TINK_USE_INSTALLED_PROTOBUF=ON, "
    "and if TINK_BUILD_TESTONLY=ON, TINK_USE_INSTALLED_GOOGLETEST=ON).")]])
endif()
