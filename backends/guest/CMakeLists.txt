set ( BACKEND_GUEST_SRCS 
  guest_svc_write.c
  guest_svc_validate.c
  guest_svc_generate.c
  common/validate.c
  common/write.c
  common/generate.c
  common/verify.c
  common/util.c
  common/read.c
  guest_svc_verify.c
  guest_svc_read.c
)

target_include_directories ( secvarctl BEFORE PRIVATE
  backends/guest/include/
)

list ( TRANSFORM BACKEND_GUEST_SRCS PREPEND ${CMAKE_CURRENT_LIST_DIR}/ )

target_sources ( secvarctl PRIVATE ${BACKEND_GUEST_SRCS} )

target_compile_definitions( secvarctl PRIVATE SECVAR_GUEST_BACKEND )
