prefix ?= /usr/local
bindir ?= $(prefix)/bin

CFLAGS = -Wall -Wextra

all: pidtrack
%: %.c
	$(CC) $(CFLAGS) -o $@ $^

install:
	install -m 755 pidtrack $(bindir)/pidtrack

uninstall:
	-rm $(bindir)/pidtrack

clean:
	$(RM) pidtrack
