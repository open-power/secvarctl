# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
cmake_minimum_required( VERSION 3.12 )
project( secvarctl C )

set( CMAKE_C_COMPILER gcc )
set( CMAKE_C_FLAGS "-MMD -O2 -std=gnu99 -Wall -Werror")
set( CMAKE_VERBOSE_MAKEFILE ON)
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )

#sources for secvarctl

set( MANDIR usr/share/man )
set ( LIB_DIR ../../build/lib	)
set( BIN_DIR . )
set( HOST_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/backends/host/ )
set( GUEST_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/backends/guest/ )
set( COMMON_DIR  ${CMAKE_CURRENT_SOURCE_DIR}/backends/common )
set( SECVARCTL_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/src/secvarctl.c ${CMAKE_CURRENT_SOURCE_DIR}/src/generic.c)
set (HOST_EXTERNAL_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/host/skiboot)
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${CMAKE_CURRENT_SOURCE_DIR}/lib")
set (BUILD_GUEST ${CMAKE_CURRENT_SOURCE_DIR}/build/guest)
set (BUILD_HOST ${CMAKE_CURRENT_SOURCE_DIR}/build/host)
set( LIB_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/build/lib)
set( CMAKE_C_FLAGS_COVERAGE    "-fprofile-arcs -ftest-coverage " )

include_directories(include ${CMAKE_CURRENT_SOURCE_DIR}/include )
option (DYNAMIC_LIB "Dynamic library " OFF)
if( ${DYNAMIC_LIB} )
	set ( DYNAMIC_LIB 1)
else( )
	set ( DYNAMIC_LIB 0)
endif ( )

option( MEMCHECK "Enable the Memory Check OPTION" OFF )
option( DEBUG "Enable the Debug Option" OFF )
if ( DEBUG )
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
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
elseif ( GNUTLS )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lgnutls")
  add_definitions(-DSECVAR_CRYPTO_GNUTLS)
elseif( MBEDTLS )
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lmbedtls -lmbedx509 -lmbedcrypto")
  add_definitions(-DSECVAR_CRYPTO_MBEDTLS)
endif()
#
#if ( STATIC_LIB )
#  set( BUILD_SHARED_LIBRARIES OFF )
#  set( CMAKE_EXE_LINKER_FLAGS "-static -lpthread" )
#else ( )
#endif( )
option (COVERAGE "Secvarctl-cov generation" 0 )
if( ${COVERAGE} )
	set ( COVERAGE 1)
	set ( EXE_FILE secvarctl-cov)
else ( )
	set ( COVERAGE 0)
	set ( EXE_FILE secvarctl)
endif ( )

option( HOST_BACKEND "Host Backend Enabled" 1 )
if ( ${HOST_BACKEND})
	set (HOST_BACKEND 1)
else ( )
	set (HOST_BACKEND 0)
endif ( )
option( GUEST_BACKEND "Host Backend Enabled" 1 )
if ( ${GUEST_BACKEND})
	set (GUEST_BACKEND 1)
else ( )
	set (GUEST_BACKEND 0)
endif ( )
if ( HOST_BACKEND )
	include_directories(include ${HOST_EXTERNAL_BACKEND_DIR} ${HOST_EXTERNAL_BACKEND_DIR}/libstb ${HOST_EXTERNAL_BACKEND_DIR}/include ${HOST_BACKEND_DIR} )
  	add_definitions(-DSECVAR_HOST_BACKEND)
endif( )
if ( GUEST_BACKEND )
	include_directories(include ${GUEST_BACKEND_DIR}/include )
	add_definitions(-DSECVAR_GUEST_BACKEND)
endif( )

add_executable( ${EXE_FILE}  ${SECVARCTL_SRCS} )
if ( COVERAGE )
  	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_C_FLAGS_COVERAGE}")
endif ( )

if ( NOT ${GUEST_BACKEND})
	target_link_libraries( ${EXE_FILE} -lhost-backend-${CRYPTO_LIB} -L${LIB_DIRS})
elseif( NOT ${HOST_BACKEND})
	target_link_libraries( ${EXE_FILE} -lguest-backend-openssl -lstb-secvar-openssl -L${LIB_DIRS})
else ( )
	target_link_libraries( ${EXE_FILE} -lhost-backend-${CRYPTO_LIB} -lguest-backend-openssl -lstb-secvar-openssl -L${LIB_DIRS})
endif ( )
add_custom_target(generate ALL
	COMMAND @mkdir ${LIB_DIRS}
	COMMAND if [ ${GUEST_BACKEND} == 1 ]\; then mkdir ${BUILD_GUEST} && cd ${BUILD_GUEST} && cmake -DLIB_DIR=${LIB_DIRS} -DDYNAMIC_LIB=${DYNAMIC_LIB} -DCRYPTO_READ_ONLY=${CRYPTO_READ_ONLY} -DDEBUG=${DEBUG} ../../backends/guest/build/../ . && make \; fi\;
	COMMAND if [ ${HOST_BACKEND} == 1 ]\; then mkdir ${BUILD_HOST} && cd ${BUILD_HOST} && cmake -DLIB_DIR=${LIB_DIRS} -DDYNAMIC_LIB=${DYNAMIC_LIB} -DOPENSSL=${OPENSSL} -DGNUTLS=${GNUTLS} -DMBEDTLS=${MBEDTLS} -DDEBUG=${DEBUG} -DCRYPTO_READ_ONLY=${CRYPTO_READ_ONLY} ../../backends/host/build/../ . && make \; fi\;
	)

add_custom_target(install_lib
	COMMAND @mkdir -p $(DESTDIR)/usr/bin
	COMMAND install -m 0755 ${EXE_FILE} $(DESTDIR)/usr/bin/secvarctl
	COMMAND mkdir -p $(DESTDIR)/$(MANDIR)man1
	COMMAND install -m 0644 ${CMAKE_CURRENT_SOURCE_DIR}/secvarctl.1 $(DESTDIR)/$(MANDIR)/man1
	COMMAND @mkdir -p $(DESTDIR)/usr/lib/secvarctl
	COMMAND install -m 0755 ${LIB_DIRS}/* $(DESTDIR)/usr/lib/secvarctl
	COMMAND if [ ${DYNAMIC_LIB} == 1 ]\; then echo "$(DESTDIR)/usr/lib/secvarctl" > /etc/ld.so.conf.d/secvarctl.conf && ldconfig \; fi\;
	COMMAND @echo "Secvarctl installed successfully!"
	)

add_custom_target(uninstall
	COMMAND @rm -rf $(DESTDIR)/usr/bin/secvarctl
	COMMAND @rm -rf $(DESTDIR)/$(MANDIR)/man1/secvarctl.1
	COMMAND @rm -rf $(DESTDIR)/usr/lib/secvarctl
	COMMAND if [ ${DYNAMIC_LIB} == 1 ]\; then rm -rf /etc/ld.so.conf.d/secvarctl.conf && ldconfig \; fi\;
	COMMAND @echo "secvarctl uninstalled successfully!"
	)

add_custom_target(clean_build
	COMMAND if [ -d ${BUILD_GUEST} ]\; then make -C ${BUILD_GUEST} Makefile clean \; fi\;
	COMMAND make -C ../external/guest/libstb-secvar/ Makefile clean
	#COMMAND @cd ${BUILD_GUEST} && make clean
	COMMAND if [ -d ${BUILD_HOST} ]\; then cd ${BUILD_HOST} && make clean \; fi\;
	#COMMAND @cd ${BUILD_HOST} && make clean
	COMMAND @rm -rf ${CMAKE_CURRENT_SOURCE_DIR}/build/*
	COMMAND @rm -rf ${LIB_DIRS}/*
        )
