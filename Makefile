PROG_NAME	:= bpfsbox
KERN_SRC	:= sandbox_uid.ebpf.c
USER_SRC	:= user.ebpf.c

CLANG       := clang
PKG_CONFIG	?= pkg-config

KERN_CFLAGS := \
  	-O2 -g -v                                 \
  	-target bpf                               \
  	-Wall -Werror                             \
  	-I.

USER_CFLAGS 	:= -O2 -g -v -Wall -Wextra
USER_LDFLAGS 	:= $(shell $(PKG_CONFIG) --libs libbpf libelf zlib) -lelf -lz

KERN_OBJ    := $(KERN_SRC:.c=.o)

all: $(KERN_OBJ) $(PROG_NAME)

$(KERN_OBJ): $(KERN_SRC)  
	$(CLANG) $(KERN_CFLAGS) -c $< -o $@

$(PROG_NAME): $(USER_SRC)
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

.PHONY: clean

clean:
	rm $(KERN_OBJ) $(PROG_NAME)

headers:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
