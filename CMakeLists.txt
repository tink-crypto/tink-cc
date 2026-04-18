cmake_minimum_required(VERSION 3.22)

project(Tink VERSION 2.6.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)
option(TINK_USE_SYSTEM_OPENSSL "Build Tink linking to OpenSSL installed in the system" OFF)
option(TINK_USE_INSTALLED_ABSEIL "Build Tink linking to Abseil installed in the system" OFF)
option(TINK_USE_INSTALLED_GOOGLETEST "Build Tink linking to GTest installed in the system" OFF)
option(TINK_USE_INSTALLED_PROTOBUF "Build Tink linking to Protobuf installed in the system" OFF)
option(USE_ONLY_FIPS "Enables the FIPS only mode in Tink" OFF)
option(TINK_INSTALL "Generate install rules for Tink" OFF)

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
include(TinkUtil)

# Bazel rewrites import paths so that "cc/example/foo.h" can be included as
# "tink/example/foo.h". The following lines simulate this behaviour by creating
# a symlink to cc/ called tink/, and placing it in a separate subdirectory,
# which is then specified as a global include path.
#
# It's important to create a separate directory and not just drop the link in
# CMAKE_CURRENT_BINARY_DIR, since adding that to the include paths will
# make the whole contents of that directory visible to the compiled files,
# which may result in undeclared dependencies that nevertheless happen to work.
#
set(TINK_INCLUDE_ALIAS_DIR "${CMAKE_CURRENT_BINARY_DIR}/__include_alias")
add_directory_alias(
  "${CMAKE_CURRENT_SOURCE_DIR}/tink" "${TINK_INCLUDE_ALIAS_DIR}/tink")
list(APPEND TINK_INCLUDE_DIRS "${TINK_INCLUDE_ALIAS_DIR}")

add_subdirectory(tink)
add_subdirectory(proto)

if(TINK_INSTALL)
  include(GNUInstallDirs)
  include(CMakePackageConfigHelpers)

  if(NOT TINK_USE_SYSTEM_OPENSSL)
    message(FATAL_ERROR "TINK_INSTALL=ON requires TINK_USE_SYSTEM_OPENSSL=ON")
  endif()
  if(NOT TINK_USE_INSTALLED_ABSEIL)
    message(FATAL_ERROR "TINK_INSTALL=ON requires TINK_USE_INSTALLED_ABSEIL=ON")
  endif()
  if(NOT TINK_USE_INSTALLED_PROTOBUF)
    message(FATAL_ERROR "TINK_INSTALL=ON requires TINK_USE_INSTALLED_PROTOBUF=ON")
  endif()

  get_property(_tink_all_targets GLOBAL PROPERTY TINK_ALL_TARGETS)

  install(
    TARGETS ${_tink_all_targets}
    EXPORT tinkTargets
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  )

  # Install source headers preserving directory structure.
  install(DIRECTORY tink/
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tink"
    FILES_MATCHING PATTERN "*.h"
  )

  # Install generated proto headers.
  install(DIRECTORY "${TINK_GENFILE_DIR}/proto/"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/proto"
    FILES_MATCHING PATTERN "*.pb.h"
  )

  # Install generated version.h.
  install(FILES "${TINK_GENFILE_DIR}/tink/version.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/tink"
  )

  # Export set.
  install(EXPORT tinkTargets
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tink"
  )

  # Generate aliases file that recreates tink::module::name aliases
  # and the tink::static convenience alias.
  get_property(_tink_alias_map GLOBAL PROPERTY TINK_ALIAS_MAP)
  set(_aliases_content "# Auto-generated alias targets for tink-cc.\n")
  foreach(_pair IN LISTS _tink_alias_map)
    string(REPLACE "=" ";" _kv "${_pair}")
    list(GET _kv 0 _alias)
    list(GET _kv 1 _real)
    string(APPEND _aliases_content
      "if(TARGET ${_real} AND NOT TARGET ${_alias})\n"
      "  add_library(${_alias} ALIAS ${_real})\n"
      "endif()\n")
  endforeach()
  string(APPEND _aliases_content
    "if(TARGET tink_core_cc AND NOT TARGET tink::static)\n"
    "  add_library(tink::static ALIAS tink_core_cc)\n"
    "endif()\n")
  file(GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/tinkAliases.cmake"
    CONTENT "${_aliases_content}")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tinkAliases.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tink")

  # Package version file.
  write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/tinkConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

  # Package config file.
  configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/tinkConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tinkConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tink")

  install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/tinkConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/tinkConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/tink")
endif()
