# Examine me if you wish, but we will learn about Makefiles in a later
# lecture.  This file allows us to automate tedious repetitive build
# commands
CFLAGS = -D_POSIX_SOURCE -Wall -Werror -pedantic -std=c99 -D_GNU_SOURCE -pthread
GCC = gcc $(CFLAGS)


APPS = firewallSetup 

all: $(APPS)

firewallSetup: firewallSetup.c
	$(GCC) -o firewallSetup firewallSetup.c

clean:
	rm -f $(APPS) 
