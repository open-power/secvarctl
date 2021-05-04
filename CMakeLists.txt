# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
cmake_minimum_required( VERSION 3.12 )
project( secvarctl C )

set( CMAKE_C_COMPILER gcc )
#sources for secvarctl
set( SRC secvarctl.c generic.c )

#sources for edk2 backend
set ( EDK2SRC edk2-svc-read.c edk2-svc-write.c edk2-svc-validate.c edk2-svc-verify.c edk2-svc-generate.c )
set ( EDK2SRCDIR backends/edk2-compat/ )
list( TRANSFORM EDK2SRC PREPEND ${EDK2SRCDIR} )
list( APPEND SRC ${EDK2SRC} )

#sources for borrowed skiboot code
set ( SKIBOOTSRC secvar_util.c backend/edk2-compat.c backend/edk2-compat-process.c )
set ( SKIBOOTSRCDIR external/skiboot/libstb/secvar/ )
list( TRANSFORM SKIBOOTSRC PREPEND ${SKIBOOTSRCDIR} )
list( APPEND SRC ${SKIBOOTSRC} )

# include paths:
#  - include/
#  - the root directory so that we can e.g. #include "{external,backends}/..."
include_directories(include ${CMAKE_CURRENT_SOURCE_DIR})

#User specified options 

#OPENSSL compiles with openssl instead of mbedtls = no extra sources
option( OPENSSL "Compile with OpenSSL as crypto library, default mbedtls")
if ( OPENSSL )
  #sources for crypto function implemented w
  set( CRYPTOSRC crypto-openssl.c )
  set( CRYPTOSRCDIR crypto/ )
  list( TRANSFORM CRYPTOSRC PREPEND ${CRYPTOSRCDIR} )
else ()
  #sources/dependencies for extra mbedtls functions
  set( EXTRAMBEDTLSDEP generate-pkcs7.h pkcs7.h )
  set( EXTRAMBEDTLSDEPDIR external/extraMbedtls/include/ )
  list( TRANSFORM EXTRAMBEDTLSDEP PREPEND ${EXTRAMBEDTLSDEPDIR} )
  set ( EXTRAMBEDTLSSRC generate-pkcs7.c pkcs7.c )
  set ( EXTRAMBEDTLSSRCDIR  external/extraMbedtls/ )
  list( TRANSFORM EXTRAMBEDTLSSRC PREPEND ${EXTRAMBEDTLSSRCDIR} )
  list( APPEND DEPEN ${EXTRAMBEDTLSDEP} )
  list( APPEND SRC ${EXTRAMBEDTLSSRC} )
  #sources for crypto function implemented w secvarctl
  set( CRYPTOSRC crypto-mbedtls.c )
  set( CRYPTOSRCDIR crypto/ )
  list( TRANSFORM CRYPTOSRC PREPEND ${CRYPTOSRCDIR} )
endif()
list ( APPEND SRC ${CRYPTOSRC} )

option( STATIC "Create statically linked executable" OFF )
if ( STATIC )
  set( BUILD_SHARED_LIBRARIES OFF )
  set( CMAKE_EXE_LINKER_FLAGS "-static" )
  set( PTHREAD "pthread" )
endif(  )

#Strip resulting executable for minimal size
option( STRIP "Strip executable of extra data for minimal size" OFF )
if ( STRIP )
  set( BUILD_SHARED_LIBRARIES OFF )
  string( APPEND CMAKE_C_FLAGS "-s" )
endif(  )


add_executable( secvarctl ${SRC} )

#no crypto means don't compile the generate command = smaller executable
option( NO_CRYPTO "Build without crypto functions for smaller executable, some functionality lost" OFF )
if ( NO_CRYPTO )
  target_compile_definitions( secvarctl PRIVATE  NO_CRYPTO )
endif(  )

#append possible extensions for library
LIST( APPEND CMAKE_FIND_LIBRARY_SUFFIXES ".so.0" ".a" ".so" )

#if compiling with openssl, get libraries
if (OPENSSL)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(secvarctl OpenSSL::SSL)
  target_compile_definitions( secvarctl PRIVATE  OPENSSL )
#else get mbedtls libraries
else()
  #get mbedtls if custom path defined
  if ( DEFINED CUSTOM_MBEDTLS )
      find_library( MBEDX509 mbedx509 PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
      find_library( MBEDCRYPTO mbedcrypto PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
      find_library( MBEDTLS mbedtls PATHS ${CUSTOM_MBEDTLS}/library NO_DEFAULT_PATH REQUIRED )
      include_directories( ${CUSTOM_MBEDTLS}/include ) 
  else(  )
      find_library( MBEDX509 mbedx509 HINTS ENV PATH REQUIRED )
      find_library( MBEDCRYPTO mbedcrypto HINTS ENV PATH REQUIRED )
      find_library( MBEDTLS mbedtls HINTS ENV PATH REQUIRED )
  endif (  )
  target_link_libraries( secvarctl ${MBEDTLS} ${MBEDX509} ${MBEDCRYPTO} ${PTHREAD} )
  target_compile_definitions( secvarctl PRIVATE  MBEDTLS ) 
endif()


#set default build type to release
set( DEFAULT_BUILD_TYPE "Debug" )
if ( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE ${DEFAULT_BUILD_TYPE} )
    message( "Setting build type to default: " ${CMAKE_BUILD_TYPE} )
endif(  )
#allow for different optimizations here
set( CMAKE_C_FLAGS_RELEASE     "-O2 -g" )
set( CMAKE_C_FLAGS_DEBUG       "-O0 -g3 -Wall -Werror" )
set( CMAKE_C_FLAGS_COVERAGE    "-O0 -g3 -fprofile-arcs -ftest-coverage -Wall -Werror" )


#set c standard
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )

install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/secvarctl.1 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man1 )
install( TARGETS secvarctl DESTINATION bin )
