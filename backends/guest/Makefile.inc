INCLUDES += -I./backends/guest/include

_CFLAGS += -DSECVAR_GUEST_BACKEND

GUEST_SRCS = guest_svc_write.c \
             guest_svc_validate.c \
             guest_svc_generate.c \
             common/validate.c \
             common/write.c \
             common/generate.c \
             common/verify.c \
             common/util.c \
             common/read.c \
             guest_svc_verify.c \
             guest_svc_read.c

MAIN_SRCS += $(addprefix backends/guest/,$(GUEST_SRCS))
