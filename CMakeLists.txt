# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 IBM Corp.

cmake_minimum_required( VERSION 3.12 )
project( secvarctl C )

add_executable( secvarctl )

target_sources( secvarctl PRIVATE secvarctl.c generic.c )

target_include_directories( secvarctl BEFORE PRIVATE
  ./
  include/
  external/libstb-secvar/
  external/libstb-secvar/include/
  external/libstb-secvar/include/secvar/
  external/libstb-secvar/external/
)

# Extract version string from VERSION
file( STRINGS VERSION VERSION_DATA REGEX "=[0-9\-]*$")
list( TRANSFORM VERSION_DATA STRIP )
list( TRANSFORM VERSION_DATA REPLACE "([^=]+)=(.*)" "set(\\1 \"\\2\")\n" )
cmake_language(EVAL CODE ${VERSION_DATA})
set( SECVARCTL_VERSION "${SECVARCTL_VERSION_MAJOR}.${SECVARCTL_VERSION_MINOR}.${SECVARCTL_VERSION_PATCH}${SECVARCTL_VERSION_EXTRA}")

message( STATUS "Detected version string as ${SECVARCTL_VERSION}" )

target_compile_definitions( secvarctl PRIVATE
  SECVAR_CRYPTO_WRITE_FUNC
  SECVARCTL_VERSION=\"${SECVARCTL_VERSION}\"
)

# Backend selection
option( HOST_BACKEND "Build with the host backend enabled" ON )
option( GUEST_BACKEND "Build with the guest backend enabled" ON )

if( HOST_BACKEND )
  include( backends/host/CMakeLists.txt )
endif()
if( GUEST_BACKEND )
  include( backends/guest/CMakeLists.txt )
endif()
if( NOT ( HOST_BACKEND OR GUEST_BACKEND) )
  message( FATAL_ERROR "No backends are enabled, refusing to build." )
endif()

# Crypto library selection
set( CRYPTO "openssl" CACHE STRING "Crypto library to use" )
set_property( CACHE CRYPTO PROPERTY STRINGS openssl mbedtls gnutls )
get_property( CRYPTO_STRINGS CACHE CRYPTO PROPERTY STRINGS )
if (NOT CRYPTO IN_LIST CRYPTO_STRINGS)
  message(FATAL_ERROR "CRYPTO must be set to one of: ${CRYPTO_STRINGS}")
endif()
message( STATUS "Using ${CRYPTO} for crypto")

if( CRYPTO STREQUAL openssl )
  target_compile_definitions( secvarctl PRIVATE SECVAR_CRYPTO_OPENSSL )
  find_package( OpenSSL REQUIRED )
  target_link_libraries( secvarctl OpenSSL::SSL )
endif()
if( CRYPTO STREQUAL mbedtls )
  target_include_directories( secvarctl AFTER PRIVATE external/extraMbedtls/include/ )
  target_sources( secvarctl PRIVATE
    external/extraMbedtls/pkcs7.c
    external/extraMbedtls/pkcs7_write.c
    external/skiboot/libstb/secvar/crypto/crypto-mbedtls.c
  )
  target_compile_definitions( secvarctl PRIVATE SECVAR_CRYPTO_MBEDTLS )
  find_library( MBEDX509 mbedx509 HINTS ENV PATH REQUIRED )
  find_library( MBEDCRYPTO mbedcrypto HINTS ENV PATH REQUIRED )
  find_library( MBEDTLS mbedtls HINTS ENV PATH REQUIRED )
  target_link_libraries( secvarctl ${MBEDTLS} ${MBEDX509} ${MBEDCRYPTO} ${PTHREAD} )
endif()
if( CRYPTO STREQUAL gnutls )
  message( FATAL_ERROR "gnutls is not currently supported for cmake builds" )
endif()

add_subdirectory( external/libstb-secvar )
target_link_libraries( secvarctl stb-secvar-openssl )

set( DEBUG_FLAGS "-O0 -g3 -Wall -Werror" )
set( COVERAGE_FLAGS "-fprofile-arcs -ftest-coverage" )
set( SANITIZE_FLAGS
  "-fsanitize=address"
  "-fsanitize=undefined"
  "-fno-sanitize-recover=all"
  "-fsanitize=float-divide-by-zero"
  "-fsanitize=float-cast-overflow"
  "-fno-sanitize=null"
  "-fno-sanitize=alignment"
)

set( CMAKE_CONFIGURATION_TYPES "Debug" "Release" )
set( DEFAULT_BUILD_TYPE "Debug" )
if ( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE ${DEFAULT_BUILD_TYPE} )
    message( "Setting build type to default: " ${CMAKE_BUILD_TYPE} )
endif(  )
set( CMAKE_C_FLAGS_RELEASE "-O2 -g" )
set( CMAKE_C_FLAGS_DEBUG   "${DEBUG_FLAGS} ${COVERAGE_FLAGS}" )

option( USE_ASAN "Build with address sanitizers" OFF )
if( USE_ASAN )
  target_compile_options( secvarctl PRIVATE ${SANITIZE_FLAGS} )
  target_link_options( secvarctl PRIVATE ${SANITIZE_FLAGS} )
endif(  )

install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/secvarctl.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1 )
install( TARGETS secvarctl DESTINATION bin )
