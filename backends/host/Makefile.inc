INCLUDES += -I./external/skiboot               \
            -I./external/skiboot/libstb        \
            -I./external/skiboot/include       \
            -I./backends/host

_CFLAGS += -DSECVAR_HOST_BACKEND

HOST_SRCS = host_svc_generate.c \
            host_svc_read.c \
            host_svc_validate.c \
            host_svc_verify.c \
            host_svc_write.c

MAIN_SRCS += $(addprefix backends/host/,$(HOST_SRCS))

EXTERNAL_SRCS += \
                 external/skiboot/libstb/secvar/secvar_util.c                 \
                 external/skiboot/libstb/secvar/backend/edk2-compat.c         \
                 external/skiboot/libstb/secvar/backend/edk2-compat-process.c
