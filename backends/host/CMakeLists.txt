# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
cmake_minimum_required( VERSION 3.12 )
project( host_backend C )

set( CMAKE_C_COMPILER gcc )
set( CMAKE_C_FLAGS "-Wall -Werror -MMD -ggdb3 -fPIC")
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )
set ( CMAKE_VERBOSE_MAKEFILE ON)

set ( HOST_EXTERNAL_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../external/host/skiboot )
set ( SKIBOOT_DIR ${HOST_EXTERNAL_BACKEND_DIR}/libstb/secvar )
set ( MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../external/host/extraMbedtls )
set ( CRYPTO_SRC )
#set ( LIB_DIR ./lib )
set (SRCS ./host_svc_read.c
          ./host_svc_write.c
          ./host_svc_validate.c
          ./host_svc_verify.c
          ./host_svc_generate.c
          ${SKIBOOT_DIR}/secvar_util.c
          ${SKIBOOT_DIR}/backend/edk2-compat.c
          ${SKIBOOT_DIR}/backend/edk2-compat-process.c )

include_directories(../../include/ ${HOST_EXTERNAL_BACKEND_DIR} ${HOST_EXTERNAL_BACKEND_DIR}/libstb/ ${HOST_EXTERNAL_BACKEND_DIR}/include/ ./ )
option (DYNAMIC_LIB "Dynamic library " OFF)
if ( ${DYNAMIC_LIB} )
	set (CMAKE_EXE_LINKER_FLAGS " ${CMAKE_EXE_LINKER_FLAGS} gcc " )
	set ( BUILD_T SHARED)
else( )
	set (CMAKE_EXE_LINKER_FLAGS " ${CMAKE_EXE_LINKER_FLAGS} ar -rcs " )
	set ( BUILD_T STATIC)
endif ( )

option( LIB_DIR "set library path " ${CMAKE_CURRENT_SOURCE_DIR}/build/lib )

if (EXISTS "${LIB_DIR}")
        set (COPY_FROM ${LIB_DIR}/../host/libhost* )
else ( )

        set ( LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build/lib )
	file(MAKE_DIRECTORY ${LIB_DIR})
        set (COPY_FROM ${LIB_DIR}/../libhost* )
endif ( )

option( DEBUG "Enable the Debug Option" OFF )
if ( DEBUG )
   set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} " -g")
else( )
   set(CMAKE_EXE_LINKER_FLAGS "-s")
endif()

option( CRYPTO_READ_ONLY "Build without crypto write functions for smaller executable, some functionality lost" OFF )
if ( NOT CRYPTO_READ_ONLY )
  add_definitions(-DSECVAR_CRYPTO_WRITE_FUNC)
endif(  )

option( OPENSSL "Compile with OpenSSL as crypto library" ON )
option( GNUTLS "Compile with GnuTLS as crypto library")
option( MBEDTLS "Compile with MbedTLS as crypto library")
set ( CRYPTO_LIB openssl )

if ( GNUTLS )
	set ( OPENSSL 0 )
	set ( MBEDTLS 0 )
	set ( CRYPTO_LIB gnutls )
endif()
if ( MBEDTLS )
	set ( OPENSSL 0 )
	set ( GNUTLS 0 )
	set ( CRYPTO_LIB mbedtls )
endif()

if ( OPENSSL )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lcrypto")
  add_definitions(-DSECVAR_CRYPTO_OPENSSL)
  set ( CRYPTO_SRC ${SKIBOOT_DIR}/crypto/crypto-openssl.c )
elseif ( GNUTLS )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgnutls")
  add_definitions(-DSECVAR_CRYPTO_GNUTLS)
  set ( CRYPTO_SRC ${SKIBOOT_DIR}/crypto/crypto-gnutls.c )
elseif( MBEDTLS )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lmbedtls -lmbedx509 -lmbedcrypto")
  add_definitions(-DSECVAR_CRYPTO_MBEDTLS)
  set ( CRYPTO_SRC ${MBEDTLS_DIR}/pkcs7_write.c ${MBEDTLS_DIR}/pkcs7.c )
  include_directories(${MBEDTLS_DIR}/include)
endif()

message("HOST BACKEND ${BUILD_T} LIBRARY")
add_library( host-backend-${CRYPTO_LIB} ${BUILD_T} ${SRCS} ${CRYPTO_SRC} )

add_custom_command(
        TARGET host-backend-${CRYPTO_LIB} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${COPY_FROM}
                ${LIB_DIR}
                COMMAND rm -rf ${COPY_FROM}
        )

add_custom_target(clean_build
        COMMAND rm -rf ${LIB_DIR}
        COMMAND rm -rf ${CMAKE_SOURCE_DIR}/build/*)
