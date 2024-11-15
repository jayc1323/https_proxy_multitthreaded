

CC = gcc
CFLAGS = -g -std=gnu99 -Wall -Wextra -Werror -Wfatal-errors -pedantic
INCLUDES = -I/usr/include/openssl
LDFLAGS = -L/usr/lib/openssl -lssl -lcrypto


src = main.c proxy.c
obj = $(src:.c=.o)

all: a.out


a.out: $(obj)
	$(CC) $(obj) -o a.out $(CFLAGS) $(LDFLAGS)


%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@


.PHONY: clean
clean:
	rm -f $(obj) a.out
