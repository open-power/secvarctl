INCLUDES += -I./external/skiboot               \
            -I./external/skiboot/libstb        \
            -I./external/skiboot/include       \
            -I./external/extraMbedtls/include/ \
            -I./backends/host

_CFLAGS += -DSECVAR_HOST_BACKEND

HOST_SRCS = host_svc_generate.c \
            host_svc_read.c \
            host_svc_validate.c \
            host_svc_verify.c \
            host_svc_write.c

MAIN_SRCS += $(addprefix backends/host/,$(HOST_SRCS))
