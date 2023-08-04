# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 IBM Corp.

cmake_minimum_required( VERSION 3.12 )
project( secvarctl C )

add_executable( secvarctl )

target_sources( secvarctl PRIVATE secvarctl.c generic.c )

set( INCLUDE_PATHS
  include/
  external/libstb-secvar/
  external/libstb-secvar/include/
  external/libstb-secvar/include/secvar/
  external/skiboot/
  external/skiboot/libstb/
  external/skiboot/include/
  external/extraMbedtls/include/
  backends/host/
  backends/guest/include/
)

target_sources( secvarctl PRIVATE
  external/extraMbedtls/pkcs7.c
  external/extraMbedtls/pkcs7_write.c
  external/skiboot/libstb/secvar/secvar_util.c
  # external/skiboot/libstb/secvar/crypto/crypto-mbedtls.c
  external/skiboot/libstb/secvar/crypto/crypto-openssl.c
  # external/skiboot/libstb/secvar/crypto/crypto-gnutls.c
  external/skiboot/libstb/secvar/backend/edk2-compat.c
  external/skiboot/libstb/secvar/backend/edk2-compat-process.c
)

include( backends/host/CMakeLists.txt )
include( backends/guest/CMakeLists.txt )

target_include_directories( secvarctl AFTER PRIVATE ${INCLUDE_PATHS} )
target_compile_definitions( secvarctl PRIVATE
  SECVAR_HOST_BACKEND
  SECVAR_GUEST_BACKEND
  SECVAR_CRYPTO_WRITE_FUNC
)

# OpenSSL
target_compile_definitions( secvarctl PRIVATE SECVAR_CRYPTO_OPENSSL )
find_package( OpenSSL REQUIRED )
target_link_libraries( secvarctl OpenSSL::SSL )

# mbedTLS
find_library( MBEDX509 mbedx509 HINTS ENV PATH REQUIRED )
find_library( MBEDCRYPTO mbedcrypto HINTS ENV PATH REQUIRED )
find_library( MBEDTLS mbedtls HINTS ENV PATH REQUIRED )
target_link_libraries( secvarctl ${MBEDTLS} ${MBEDX509} ${MBEDCRYPTO} ${PTHREAD} )

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
