set ( BACKEND_HOST_SRCS
  host_svc_generate.c
  host_svc_read.c
  host_svc_validate.c
  host_svc_verify.c
  host_svc_write.c
)

list ( TRANSFORM BACKEND_HOST_SRCS PREPEND ${CMAKE_CURRENT_LIST_DIR}/ )

target_sources ( secvarctl PRIVATE ${BACKEND_HOST_SRCS} )
