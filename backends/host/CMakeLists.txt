set ( BACKEND_HOST_SRCS
  host_svc_generate.c
  host_svc_read.c
  host_svc_validate.c
  host_svc_verify.c
  host_svc_write.c
)

target_include_directories ( secvarctl AFTER PRIVATE
  external/skiboot/
  external/skiboot/libstb/
  external/skiboot/include/
  backends/host/
)

list ( TRANSFORM BACKEND_HOST_SRCS PREPEND ${CMAKE_CURRENT_LIST_DIR}/ )

target_sources ( secvarctl PRIVATE ${BACKEND_HOST_SRCS} )

# External dependencies
target_sources ( secvarctl PRIVATE
  external/skiboot/libstb/secvar/secvar_util.c
  external/skiboot/libstb/secvar/backend/edk2-compat.c
  external/skiboot/libstb/secvar/backend/edk2-compat-process.c
)

target_compile_definitions ( secvarctl PRIVATE SECVAR_HOST_BACKEND )
