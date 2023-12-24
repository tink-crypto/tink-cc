cmake_minimum_required(VERSION 3.13)
project(tink VERSION 2.1.1 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(TINK_BUILD_TESTS "Build Tink tests" OFF)
option(TINK_USE_SYSTEM_OPENSSL "Build Tink linking to OpenSSL installed in the system" OFF)
option(TINK_USE_INSTALLED_ABSEIL "Build Tink linking to Abseil installed in the system" OFF)
option(TINK_USE_INSTALLED_GOOGLETEST "Build Tink linking to GTest installed in the system" OFF)
option(TINK_USE_INSTALLED_PROTOBUF "Build Tink linking to Protobuf installed in the system" OFF)
option(TINK_USE_INSTALLED_RAPIDJSON "Build Tink linking to Rapidjson installed in the system" OFF)
option(USE_ONLY_FIPS "Enables the FIPS only mode in Tink" OFF)
option(TINK_BUILD_SHARED_LIB "Build libtink bundle it with the headers" OFF)

if (TINK_BUILD_SHARED_LIB)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "libtink override" FORCE)
endif()

set(CPACK_GENERATOR TGZ)
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

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

if (TINK_BUILD_SHARED_LIB)
  install(
    DIRECTORY
      "${CMAKE_CURRENT_SOURCE_DIR}/tink/"
      "${TINK_GENFILE_DIR}/tink/"
    DESTINATION "include/tink"
    FILES_MATCHING PATTERN "*.h"
  )

  install(
    DIRECTORY
      "${TINK_GENFILE_DIR}/proto"
    DESTINATION "include"
    FILES_MATCHING PATTERN "*.h"
  )

  export(EXPORT Tink FILE tinkConfig.cmake)
  install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
  )
endif()
