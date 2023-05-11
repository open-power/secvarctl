# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
cmake_minimum_required( VERSION 3.12 )
project( Guest_Backend C )

set( CMAKE_C_COMPILER gcc )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-error -MMD -ggdb3 -fPIC")
#set c standard
set( CMAKE_C_STANDARD 99 )
set( CMAKE_C_STANDARD_REQUIRED ON )
set(CMAKE_VERBOSE_MAKEFILE ON)
option( LIB_DIR "set library path " ${CMAKE_CURRENT_SOURCE_DIR}/build/lib )
set( COMMON_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/common)
set( GUEST_EXTERNAL_BACKEND_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../external/guest/libstb-secvar)
set( GUEST_EXTERNAL_BACKEND ${CMAKE_CURRENT_SOURCE_DIR}/../../external/guest)
add_definitions(-DSECVAR_CRYPTO_OPENSSL)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../include/ ${GUEST_EXTERNAL_BACKEND_DIR}/include ${GUEST_EXTERNAL_BACKEND_DIR}/include/secvar ${CMAKE_CURRENT_SOURCE_DIR}/include ${GUEST_EXTERNAL_BACKEND_DIR} ${GUEST_EXTERNAL_BACKEND_DIR}/external/endian )
option (DYNAMIC_LIB "Dynamic library " OFF)
option (STATIC_LIB "Static library " ON)
if( ${DYNAMIC_LIB} )
	set ( STATIC_LIB 0)
	set (CMAKE_EXE_LINKER_FLAGS " ${CMAKE_EXE_LINKER_FLAGS} gcc " )
	set ( BUILD_T SHARED)
else( )
	set ( STATIC_LIB 1)
	set (CMAKE_EXE_LINKER_FLAGS " ${CMAKE_EXE_LINKER_FLAGS} ar -rcs " )
	set ( BUILD_T STATIC)
endif ( )	

option( DEBUG "Enable the Debug Option" OFF )
if ( DEBUG )
   set(CMAKE_C_FLAGS " ${CMAKE_C_FLAGS} -g")
else( )
   set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s")
endif()
option( CRYPTO_READ_ONLY "Build without crypto write functions for smaller executable, some functionality lost" OFF )
if ( NOT CRYPTO_READ_ONLY )
  set( CRYPTO_READ_ONLY 0)
  add_definitions(-DSECVAR_CRYPTO_WRITE_FUNC)
endif(  )

set(CMAKE_EXE_LINKER_FLAGS "-lcrypto -lstb-secvar-openssl -L${LIB_DIR} ")

set (SRCS ${COMMON_SRC_DIR}/util.c 
	${COMMON_SRC_DIR}/write.c 
        ${COMMON_SRC_DIR}/verify.c 
        ${COMMON_SRC_DIR}/validate.c 
        ${COMMON_SRC_DIR}/read.c 
        ${COMMON_SRC_DIR}/generate.c 
       ./guest_svc_write.c 
       ./guest_svc_verify.c 
       ./guest_svc_validate.c 
       ./guest_svc_read.c 
       ./guest_svc_generate.c)

if (EXISTS "${LIB_DIR}")
	set (COPY_FROM ${LIB_DIR}/../guest/libguest* )
else ( )
	set ( LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build/lib )
	set (COPY_FROM ${LIB_DIR}/../libguest* )
endif ( )
add_custom_target (generate ALL
	COMMAND git submodule update --recursive --init --remote
	COMMAND make -C ${GUEST_EXTERNAL_BACKEND_DIR} -f Makefile LIB_DIR=${LIB_DIR} STATIC_LIB=${STATIC_LIB} CRYPTO_READ_ONLY=${CRYPTO_READ_ONLY})

message("GUEST BACKEND ${BUILD_T} LIBRARY")
add_library( guest-backend-openssl ${BUILD_T} ${SRCS})

add_custom_command(
        TARGET guest-backend-openssl POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
		${COPY_FROM}
                ${LIB_DIR}
		COMMAND rm -rf ${COPY_FROM}
	)

add_custom_target(clean_build 
	COMMAND make -C ${GUEST_EXTERNAL_BACKEND_DIR} clean
	COMMAND find $(COMMON_SRC_DIR) -name "*.[od]" -delete
	COMMAND find . -name "*.[od]" -delete
	COMMAND rm -rf ${LIB_DIR}
	COMMAND rm -rf ${CMAKE_SOURCE_DIR}/build/*)
