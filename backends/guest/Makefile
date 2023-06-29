CC = gcc
_CFLAGS += -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

LIB_DIR=./lib
COMMON_SRC_DIR = ./common
GUEST_EXTERNAL_BACKEND_DIR = ../../external/guest/libstb-secvar
GUEST_EXTERNAL_BACKEND = ../../external/guest

INCLUDES = -I../../include \
           -I$(GUEST_EXTERNAL_BACKEND_DIR)/include \
           -I$(GUEST_EXTERNAL_BACKEND_DIR)/include/secvar \
           -I$(GUEST_EXTERNAL_BACKEND_DIR) \
           -I./include

DEBUG ?= 0
ifeq ($(strip $(DEBUG)), 1)
  _CFLAGS += -g
else
  _LDFLAGS += -s
endif

#use CRYPTO_READ_ONLY for smaller executable but limited functionality
#removes all write functions (secvarctl generate, pem_to_der etc.)
CRYPTO_READ_ONLY = 0
ifeq ($(strip $(CRYPTO_READ_ONLY)), 0)
  _CFLAGS += -DSECVAR_CRYPTO_WRITE_FUNC
endif

DYNAMIC_LIB = 0
STATIC_LIB = 1
ifeq ($(strip $(DYNAMIC_LIB)), 1)
  LD = gcc
  STATIC_LIB = 0
else
  LD = ar -rcs
  STATIC_LIB = 1
endif

_CFLAGS += $(CFLAGS) $(INCLUDES)

_LDFLAGS = $(LDFLAGS) -lcrypto -lstb-secvar-openssl -L$(LIB_DIR)

SRCS = $(COMMON_SRC_DIR)/util.c \
       $(COMMON_SRC_DIR)/write.c \
       $(COMMON_SRC_DIR)/verify.c \
       $(COMMON_SRC_DIR)/validate.c \
       $(COMMON_SRC_DIR)/read.c \
       $(COMMON_SRC_DIR)/generate.c \
       ./guest_svc_write.c \
       ./guest_svc_verify.c \
       ./guest_svc_validate.c \
			 ./guest_svc_read.c \
			 ./guest_svc_generate.c

GUEST_OBJS = $(SRCS:.c=.o)

ifeq ($(LIB_DIR), ./lib)
  LIB_DIRS = ../../../backends/guest/lib
else
  LIB_DIRS = ../$(LIB_DIR)
endif

all: libstb-secvar libguest-backend-openssl

%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

libguest-backend-openssl: $(GUEST_OBJS)
ifeq ($(strip $(DYNAMIC_LIB)), 1)
	$(LD) $(_LDFLAGS) -shared $^ -o $(LIB_DIR)/$@.so
else
	$(LD) $(LIB_DIR)/$@.a $^
endif
	@echo "Guest Backend Build successful!"

libstb-secvar:
	@mkdir -p $(LIB_DIR)
	@$(MAKE) -C $(GUEST_EXTERNAL_BACKEND_DIR) LIB_DIR=$(LIB_DIRS) STATIC_LIB=$(STATIC_LIB) \
	            CRYPTO_READ_ONLY=$(CRYPTO_READ_ONLY)

clean:
	@$(MAKE) -C $(GUEST_EXTERNAL_BACKEND_DIR) clean
	find $(COMMON_SRC_DIR) -name "*.[od]" -delete
	find . -name "*.[od]" -delete
	rm -rf $(LIB_DIR)

.PHONY: all libguest-backend-openssl libstb-secvar clean
