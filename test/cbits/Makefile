CC      ?= cc
CFLAGS  := -DOOM_COMMIT -Wall -Wextra -O2 -g
CFLAGS  += -I../../cbits -I.
LDFLAGS :=

# On Linux, link libbpf; on macOS, the stubs compile without it
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  LDFLAGS += -lbpf -lelf -lz
endif

TARGET := test_monitor

.PHONY: all clean test

all: $(TARGET)

$(TARGET): test_monitor.c ../../cbits/monitor.c ../../cbits/arena.h ../../cbits/monitor.h utest.h
	$(CC) $(CFLAGS) -o $@ test_monitor.c ../../cbits/monitor.c $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
